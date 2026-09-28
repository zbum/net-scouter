package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/zbum/net-scouter/internal/flow"
	"github.com/zbum/net-scouter/internal/query"
)

func (a *Agent) SetRuntime(interfaces []string, connectionsEnabled bool, abi, detail string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.obs.Interfaces = copyStrings(interfaces)
	a.obs.ConnectionsEnabled = connectionsEnabled
	if connectionsEnabled {
		a.obs.ConnectionABI = abi
		a.obs.ConnectionDetail = ""
		return
	}
	a.obs.ConnectionABI = ""
	if detail == "" {
		detail = query.ConnectionABIUnavailable
	}
	a.obs.ConnectionDetail = detail
}

func (a *Agent) EnableStatusFile(path string) error {
	if path == "" {
		return fmt.Errorf("status path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("status directory: %w", err)
	}
	a.mu.Lock()
	a.statusPath = path
	st := a.statusLocked()
	a.mu.Unlock()
	if err := query.WriteStatus(path, st); err != nil {
		return fmt.Errorf("write status: %w", err)
	}
	return nil
}

func (a *Agent) StartQuery(ctx context.Context, socketPath string) error {
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
		return fmt.Errorf("query socket directory: %w", err)
	}
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("replace query socket: %w", err)
	}
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", socketPath, err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		ln.Close()
		return err
	}
	go func() {
		<-ctx.Done()
		ln.Close()
		os.Remove(socketPath)
	}()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go a.handleQuery(conn)
		}
	}()
	return nil
}

func (a *Agent) handleQuery(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	var req query.Request
	if err := json.NewDecoder(io.LimitReader(conn, 4096)).Decode(&req); err != nil {
		_ = json.NewEncoder(conn).Encode(query.Response{Error: "invalid query"})
		return
	}
	var resp query.Response
	switch req.Cmd {
	case "status":
		st := a.Status()
		resp = query.Response{OK: true, Status: &st}
	case "flows":
		flows, err := a.Flows()
		if err != nil {
			resp = query.Response{Error: err.Error()}
		} else {
			resp = query.Response{OK: true, Flows: &flows}
		}
	case "flows_attempts":
		flows, err := a.FlowAttempts()
		if err != nil {
			resp = query.Response{Error: err.Error()}
		} else {
			resp = query.Response{OK: true, Flows: &flows}
		}
	default:
		resp = query.Response{Error: "unknown command " + req.Cmd}
	}
	_ = json.NewEncoder(conn).Encode(resp)
}

// FlowAttempts includes current packet-only TCP rows for diagnostics.
func (a *Agent) FlowAttempts() (query.FlowsResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	raw, err := a.source.Snapshot()
	if err != nil {
		a.lastError = err.Error()
		return query.FlowsResult{}, fmt.Errorf("snapshot flows: %w", err)
	}
	if a.mode != "" {
		if err := a.ingestLocked(raw); err != nil {
			return query.FlowsResult{}, err
		}
	}
	a.mapEntries = len(raw)
	a.lastSnapshotAt = time.Now()
	records := a.visible(raw)
	result := query.PrepareFlows(records, a.obs.ConnectionsEnabled, a.obs.ConnectionABI, a.obs.ConnectionDetail)
	result.DurableStorage = a.statusLocked().DurableStorage
	_ = query.WriteStatus(a.statusPath, a.statusLocked())
	return result, nil
}

func (a *Agent) Status() query.Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.mode != "" {
		if _, err := a.observeLocked(); err != nil {
			a.lastError = err.Error()
		}
		st := a.statusLocked()
		_ = query.WriteStatus(a.statusPath, st)
		return st
	}
	records, err := a.source.Snapshot()
	if err != nil {
		a.lastError = err.Error()
		st := a.statusLocked()
		_ = query.WriteStatus(a.statusPath, st)
		return st
	}
	_, st := a.applySnapshot(records)
	_ = query.WriteStatus(a.statusPath, st)
	return st
}

func (a *Agent) Flows() (query.FlowsResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.mode != "" {
		records, err := a.observeLocked()
		if err != nil {
			a.lastError = err.Error()
			_ = query.WriteStatus(a.statusPath, a.statusLocked())
			return query.FlowsResult{}, err
		}
		_ = query.WriteStatus(a.statusPath, a.statusLocked())
		available := a.obs.ConnectionsEnabled
		for _, record := range records {
			if record.Protocol == 6 && record.Connections > 0 {
				available = true
				break
			}
		}
		result := query.PrepareFlows(records, available, a.obs.ConnectionABI, a.obs.ConnectionDetail)
		result.HistoricalConnections = available && !a.obs.ConnectionsEnabled
		result.DurableStorage = a.statusLocked().DurableStorage
		return result, nil
	}
	records, err := a.source.Snapshot()
	if err != nil {
		a.lastError = err.Error()
		_ = query.WriteStatus(a.statusPath, a.statusLocked())
		return query.FlowsResult{}, fmt.Errorf("snapshot flows: %w", err)
	}
	filtered, st := a.applySnapshot(records)
	_ = query.WriteStatus(a.statusPath, st)
	return query.PrepareFlows(filtered, a.obs.ConnectionsEnabled, a.obs.ConnectionABI, a.obs.ConnectionDetail), nil
}

func (a *Agent) applySnapshot(raw []flow.Record) ([]flow.Record, query.Status) {
	filtered := a.visible(raw)
	a.mapEntries = len(raw)
	a.lastSnapshotAt = time.Now()
	a.lastError = ""
	a.observedFrom, a.observedTo = observationWindow(filtered)
	return filtered, a.statusLocked()
}

func (a *Agent) statusLocked() query.Status {
	entries := a.mapEntries
	atCapacity := a.maxFlows > 0 && uint32(entries) >= a.maxFlows
	st := query.Status{
		Mode:           a.mode,
		Live:           true,
		Running:        true,
		Source:         "agent",
		PID:            os.Getpid(),
		StartedAt:      a.startedAt,
		LastSnapshotAt: a.lastSnapshotAt,
		Interfaces:     copyStrings(a.obs.Interfaces),
		HostAddresses:  copyStrings(a.obs.HostAddresses),
		Interval:       a.interval.String(),
		ObservedFrom:   a.observedFrom,
		ObservedTo:     a.observedTo,
		Map: query.MapStatus{
			Entries:      entries,
			MaxEntries:   a.maxFlows,
			AtCapacity:   atCapacity,
			PossibleLoss: atCapacity || a.counterRegression,
		},
		Connections: query.ConnectionStatus{
			Enabled: a.obs.ConnectionsEnabled,
			ABI:     a.obs.ConnectionABI,
			Detail:  a.obs.ConnectionDetail,
		},
		Exclude: query.ExcludeStatus{
			Destinations:  copyStrings(a.obs.Destinations),
			WorkloadCIDRs: copyStrings(a.obs.WorkloadCIDRs),
			Ingress: query.DirectionExclusions{
				Sources: copyStrings(a.obs.Ingress.Sources), Destinations: copyStrings(a.obs.Ingress.Destinations),
			},
			Egress: query.DirectionExclusions{
				Sources: copyStrings(a.obs.Egress.Sources), Destinations: copyStrings(a.obs.Egress.Destinations),
			},
		},
		DurableStorage:     query.DurableUnavailable,
		DurableReason:      query.DurableReason,
		MemoryEvictedTotal: a.memoryEvictedTotal,
		LastError:          a.lastError,
	}
	switch a.mode {
	case "exporter":
		st.DurableStorage = query.DurableDisabled
		st.DurableReason = "exporter mode keeps flows in memory only"
		st.Exporter = query.ExporterStatus{
			Listen: a.metrics.Addr(), Published: a.metricsPublished, Omitted: a.metricsOmitted, LastCollection: a.metricsCollectedAt,
		}
	case "persistent":
		st.DurableStorage = query.DurableReady
		st.DurableReason = ""
		if a.storageError != "" {
			st.DurableStorage = query.DurableDegraded
			st.DurableReason = a.storageError
		}
		st.Storage = query.StorageStatus{
			Path: a.storagePath, Schema: 1, LastFlush: a.lastFlush,
			Entries: a.storageStats.Entries, FileBytes: a.storageStats.FileBytes,
			MaxEntries: a.retention.MaxEntries, MaxBytes: a.retention.MaxBytes,
			OverMaxBytes: a.storageStats.OverMaxBytes, Retention: a.retention.InactiveTTL.String(),
			ExpiredTotal: a.storageStats.ExpiredTotal, EvictedTotal: a.storageStats.EvictedTotal,
			Error: a.storageError,
		}
	}
	return st
}

func observationWindow(records []flow.Record) (time.Time, time.Time) {
	if len(records) == 0 {
		return time.Time{}, time.Time{}
	}
	from, to := records[0].FirstSeen, records[0].LastSeen
	for _, record := range records[1:] {
		if record.FirstSeen.Before(from) {
			from = record.FirstSeen
		}
		if record.LastSeen.After(to) {
			to = record.LastSeen
		}
	}
	return from, to
}
