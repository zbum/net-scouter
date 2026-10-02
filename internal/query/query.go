package query

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/zbum/net-scouter/internal/flow"
)

const (
	RuntimeDir               = "/run/net-scouter"
	DefaultSocketPath        = "/run/net-scouter/query.sock"
	DefaultStatusPath        = "/run/net-scouter/status.json"
	DurableUnavailable       = "unavailable"
	DurableReady             = "ready"
	DurableDisabled          = "disabled"
	DurableDegraded          = "degraded"
	DurableReason            = "persistent mode is not enabled"
	ConnectionABIUnavailable = "unknown or unavailable tracepoint ABI"
)

var ErrAgentUnavailable = errors.New("agent query socket unavailable")

type Request struct {
	Cmd string `json:"cmd"`
}

type Response struct {
	OK     bool         `json:"ok"`
	Error  string       `json:"error,omitempty"`
	Status *Status      `json:"status,omitempty"`
	Flows  *FlowsResult `json:"flows,omitempty"`
}

type Status struct {
	DockerNetworks       []string         `json:"dockerNetworks"`
	DockerDiscoveryError string           `json:"dockerDiscoveryError,omitempty"`
	Mode                 string           `json:"mode"`
	Live                 bool             `json:"live"`
	Stale                bool             `json:"stale"`
	Running              bool             `json:"running"`
	Source               string           `json:"source"`
	PID                  int              `json:"pid,omitempty"`
	StartedAt            time.Time        `json:"startedAt,omitempty"`
	LastSnapshotAt       time.Time        `json:"lastSnapshotAt,omitempty"`
	Interfaces           []string         `json:"interfaces"`
	HostAddresses        []string         `json:"hostAddresses,omitempty"`
	Interval             string           `json:"interval,omitempty"`
	ObservedFrom         time.Time        `json:"observedFrom,omitempty"`
	ObservedTo           time.Time        `json:"observedTo,omitempty"`
	Map                  MapStatus        `json:"map"`
	Connections          ConnectionStatus `json:"connections"`
	Exclude              ExcludeStatus    `json:"exclude"`
	Storage              StorageStatus    `json:"storage"`
	Exporter             ExporterStatus   `json:"exporter"`
	DurableStorage       string           `json:"durableStorage"`
	DurableReason        string           `json:"durableStorageReason"`
	MemoryEvictedTotal   uint64           `json:"memoryEvictedTotal"`
	LastError            string           `json:"lastError,omitempty"`
}

type StorageStatus struct {
	Path         string    `json:"path,omitempty"`
	Schema       uint32    `json:"schema,omitempty"`
	LastFlush    time.Time `json:"lastFlush,omitempty"`
	Entries      int       `json:"entries"`
	FileBytes    int64     `json:"fileBytes"`
	MaxEntries   int       `json:"maxEntries"`
	MaxBytes     int64     `json:"maxBytes"`
	OverMaxBytes bool      `json:"overMaxBytes"`
	Retention    string    `json:"retention,omitempty"`
	ExpiredTotal uint64    `json:"expiredTotal"`
	EvictedTotal uint64    `json:"evictedTotal"`
	Error        string    `json:"error,omitempty"`
}

type ExporterStatus struct {
	Listen         string    `json:"listen,omitempty"`
	Published      int       `json:"publishedFlows"`
	Omitted        int       `json:"omittedFlows"`
	LastCollection time.Time `json:"lastCollection,omitempty"`
}

type MapStatus struct {
	Entries      int    `json:"entries"`
	MaxEntries   uint32 `json:"maxEntries"`
	AtCapacity   bool   `json:"atCapacity"`
	PossibleLoss bool   `json:"possibleLoss"`
}

type ConnectionStatus struct {
	Enabled bool   `json:"enabled"`
	ABI     string `json:"abi,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

type ExcludeStatus struct {
	Destinations  []string            `json:"destinations"`
	WorkloadCIDRs []string            `json:"workloadCIDRs"`
	Ingress       DirectionExclusions `json:"ingress"`
	Egress        DirectionExclusions `json:"egress"`
}

type DirectionExclusions struct {
	Sources      []string `json:"sources"`
	Destinations []string `json:"destinations"`
}

type FlowView struct {
	SrcIP       string         `json:"src"`
	DstIP       string         `json:"dst"`
	SrcPort     uint16         `json:"srcPort,omitempty"`
	DstPort     uint16         `json:"dstPort,omitempty"`
	Protocol    uint8          `json:"protocol"`
	Direction   flow.Direction `json:"direction"`
	FirstSeen   time.Time      `json:"firstSeen"`
	LastSeen    time.Time      `json:"lastSeen"`
	Packets     uint64         `json:"packets"`
	Bytes       uint64         `json:"bytes"`
	Connections *uint64        `json:"connections"`
}

type FlowsResult struct {
	ConnectionsAvailable  bool       `json:"connectionsAvailable"`
	HistoricalConnections bool       `json:"historicalConnections,omitempty"`
	ConnectionABI         string     `json:"connectionABI,omitempty"`
	ConnectionDetail      string     `json:"connectionDetail,omitempty"`
	DurableStorage        string     `json:"durableStorage"`
	Records               []FlowView `json:"records"`
}

func NewFlowView(r flow.Record, connectionsAvailable bool) FlowView {
	srcPort := r.SrcPort
	if r.Protocol == 6 {
		srcPort = 0
	}
	view := FlowView{
		SrcIP:     r.SrcIP.String(),
		DstIP:     r.DstIP.String(),
		SrcPort:   srcPort,
		DstPort:   r.DstPort,
		Protocol:  r.Protocol,
		Direction: r.Direction,
		FirstSeen: r.FirstSeen,
		LastSeen:  r.LastSeen,
		Packets:   r.Packets,
		Bytes:     r.Bytes,
	}
	if connectionsAvailable && r.Protocol == 6 {
		n := r.Connections
		view.Connections = &n
	}
	return view
}

func Call(ctx context.Context, socketPath string, req Request) (Response, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return Response{}, err
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return Response{}, err
	}
	return resp, nil
}

func WriteStatus(path string, st Status) error {
	if path == "" {
		return nil
	}
	body, err := json.Marshal(st)
	if err != nil {
		return err
	}
	body = append(body, '\n')
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".status-*")
	if err != nil {
		return fmt.Errorf("create status file: %w", err)
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace status file: %w", err)
	}
	ok = true
	return nil
}

func ReadStatus(path string) (Status, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return Status{}, err
	}
	var st Status
	if err := json.Unmarshal(body, &st); err != nil {
		return Status{}, fmt.Errorf("decode status file: %w", err)
	}
	return st, nil
}

func LoadStatus(socketPath, filePath string) (Status, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := Call(ctx, socketPath, Request{Cmd: "status"})
	if err == nil {
		if resp.Status == nil {
			if resp.Error == "" {
				resp.Error = "agent returned no status"
			}
			return Status{}, errors.New(resp.Error)
		}
		st := *resp.Status
		st.Live = true
		st.Stale = false
		st.Running = true
		st.Source = "agent"
		if !resp.OK {
			if resp.Error == "" {
				resp.Error = "agent status failed"
			}
			return st, errors.New(resp.Error)
		}
		return st, nil
	}
	st, readErr := ReadStatus(filePath)
	if readErr != nil {
		if os.IsNotExist(readErr) {
			return absentStatus(), nil
		}
		return Status{}, fmt.Errorf("read status file: %w", readErr)
	}
	st.Live = false
	st.Source = "status-file"
	st.Running = processAlive(st.PID)
	st.Stale = !st.Running
	return st, nil
}

func LoadFlows(socketPath string) (FlowsResult, error) {
	return loadFlows(socketPath, "flows")
}

func LoadFlowAttempts(socketPath string) (FlowsResult, error) {
	return loadFlows(socketPath, "flows_attempts")
}

func loadFlows(socketPath, command string) (FlowsResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := Call(ctx, socketPath, Request{Cmd: command})
	if err != nil {
		return FlowsResult{}, fmt.Errorf("%w on %s: %v", ErrAgentUnavailable, socketPath, err)
	}
	if !resp.OK || resp.Flows == nil {
		if resp.Error == "" {
			resp.Error = "agent returned no flows"
		}
		return FlowsResult{}, errors.New(resp.Error)
	}
	return *resp.Flows, nil
}

func absentStatus() Status {
	return Status{
		Source:         "none",
		Interfaces:     []string{},
		DurableStorage: DurableUnavailable,
		DurableReason:  DurableReason,
		Exclude: ExcludeStatus{
			Destinations:  []string{},
			WorkloadCIDRs: []string{},
			Ingress:       DirectionExclusions{Sources: []string{}, Destinations: []string{}},
			Egress:        DirectionExclusions{Sources: []string{}, Destinations: []string{}},
		},
		Connections: ConnectionStatus{Detail: "agent is not running"},
	}
}
