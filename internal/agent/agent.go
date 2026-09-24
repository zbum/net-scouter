package agent

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/example/net-scouter/internal/flow"
	"github.com/example/net-scouter/internal/query"
)

type Snapshotter interface{ Snapshot() ([]flow.Record, error) }

type Agent struct {
	source        Snapshotter
	output        io.Writer
	interval      time.Duration
	maxFlows      uint32
	destinations  []netip.Prefix
	workloads     []netip.Prefix
	hostAddresses map[netip.Addr]struct{}
	previous      map[flowIdentity]cacheEntry
	generation    uint64
	cacheLimit    int

	mu             sync.Mutex
	startedAt      time.Time
	statusPath     string
	obs            runtimeObs
	capture        captureSel
	mapEntries     int
	lastSnapshotAt time.Time
	observedFrom   time.Time
	observedTo     time.Time
	lastError      string
}

type captureSel struct {
	ipv4 bool
	ipv6 bool
	tcp  bool
	udp  bool
}

type runtimeObs struct {
	Interfaces         []string
	ConnectionsEnabled bool
	ConnectionABI      string
	ConnectionDetail   string
	Destinations       []string
	WorkloadCIDRs      []string
	HostAddresses      []string
}

type flowIdentity struct {
	source, destination         netip.Addr
	sourcePort, destinationPort uint16
	protocol                    uint8
	direction                   flow.Direction
}
type flowCounters struct {
	packets, bytes, connections uint64
	lastSeen                    time.Time
}
type cacheEntry struct {
	counters   flowCounters
	generation uint64
}

func New(source Snapshotter, output io.Writer, interval time.Duration, maxFlows uint32, destinationCIDRs, workloadCIDRs []string, hostAddrs []netip.Addr) (*Agent, error) {
	dest, err := parsePrefixes(destinationCIDRs)
	if err != nil {
		return nil, fmt.Errorf("destination exclusions: %w", err)
	}
	work, err := parsePrefixes(workloadCIDRs)
	if err != nil {
		return nil, fmt.Errorf("workload exclusions: %w", err)
	}
	if len(hostAddrs) == 0 {
		return nil, fmt.Errorf("host address scope requires at least one selected interface address")
	}
	hostAddresses := make(map[netip.Addr]struct{}, len(hostAddrs))
	hostAddressStrings := make([]string, 0, len(hostAddrs))
	for _, addr := range hostAddrs {
		addr = addr.Unmap()
		if !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() {
			return nil, fmt.Errorf("invalid host address %q", addr)
		}
		if _, exists := hostAddresses[addr]; exists {
			continue
		}
		hostAddresses[addr] = struct{}{}
		hostAddressStrings = append(hostAddressStrings, addr.String())
	}
	return &Agent{
		source:        source,
		output:        output,
		interval:      interval,
		maxFlows:      maxFlows,
		destinations:  dest,
		workloads:     work,
		hostAddresses: hostAddresses,
		previous:      make(map[flowIdentity]cacheEntry),
		cacheLimit:    int(maxFlows) * 3,
		startedAt:     time.Now(),
		capture:       captureSel{ipv4: true, ipv6: true, tcp: true, udp: true},
		obs: runtimeObs{
			Destinations:  copyStrings(destinationCIDRs),
			WorkloadCIDRs: copyStrings(workloadCIDRs),
			HostAddresses: hostAddressStrings,
		},
	}, nil
}

func copyStrings(values []string) []string {
	out := make([]string, len(values))
	copy(out, values)
	return out
}

func parsePrefixes(values []string) ([]netip.Prefix, error) {
	result := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		p, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", value, err)
		}
		result = append(result, p.Masked())
	}
	return result, nil
}

func (a *Agent) Run(ctx context.Context) error {
	if err := a.export(); err != nil {
		return err
	}
	ticker := time.NewTicker(a.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := a.export(); err != nil {
				return err
			}
		}
	}
}

func (a *Agent) export() error {
	emit, err := a.collectExport()
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(a.output)
	for _, record := range emit {
		if err := encoder.Encode(record); err != nil {
			err = fmt.Errorf("encode flow: %w", err)
			a.noteError(err)
			return err
		}
	}
	return nil
}

func (a *Agent) collectExport() ([]flow.Record, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	records, err := a.source.Snapshot()
	if err != nil {
		a.lastError = err.Error()
		if werr := query.WriteStatus(a.statusPath, a.statusLocked()); werr != nil {
			return nil, fmt.Errorf("snapshot flows: %w (status: %v)", err, werr)
		}
		return nil, fmt.Errorf("snapshot flows: %w", err)
	}
	filtered, st := a.applySnapshot(records)
	if err := query.WriteStatus(a.statusPath, st); err != nil {
		return nil, fmt.Errorf("write status: %w", err)
	}
	a.generation++
	emit := make([]flow.Record, 0, len(filtered))
	for _, record := range filtered {
		if record.Protocol == 6 && (!a.obs.ConnectionsEnabled || record.Connections == 0) {
			continue
		}
		identity := flowIdentity{record.SrcIP, record.DstIP, record.SrcPort, record.DstPort, record.Protocol, record.Direction}
		current := flowCounters{record.Packets, record.Bytes, record.Connections, record.LastSeen}
		previous, exists := a.previous[identity]
		unchanged := exists && previous.counters == current && previous.generation+1 == a.generation
		a.previous[identity] = cacheEntry{current, a.generation}
		if !unchanged {
			emit = append(emit, record)
		}
	}
	a.pruneCache()
	return emit, nil
}

func (a *Agent) noteError(err error) {
	if err == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lastError = err.Error()
	_ = query.WriteStatus(a.statusPath, a.statusLocked())
}

func (a *Agent) pruneCache() {
	for key, entry := range a.previous {
		if entry.generation+3 < a.generation {
			delete(a.previous, key)
		}
	}
	if len(a.previous) <= a.cacheLimit {
		return
	}
	type candidate struct {
		key        flowIdentity
		generation uint64
	}
	items := make([]candidate, 0, len(a.previous))
	for key, entry := range a.previous {
		items = append(items, candidate{key, entry.generation})
	}
	slices.SortFunc(items, func(x, y candidate) int { return cmp.Compare(x.generation, y.generation) })
	for _, item := range items[:len(items)-a.cacheLimit] {
		delete(a.previous, item.key)
	}
}

func (a *Agent) visible(records []flow.Record) []flow.Record {
	records = flow.ForACL(records)
	out := make([]flow.Record, 0, len(records))
	for _, record := range records {
		if !a.allows(record) || !a.fromSelectedHostAddress(record) || a.excluded(record) {
			continue
		}
		out = append(out, record)
	}
	return out
}

func (a *Agent) fromSelectedHostAddress(r flow.Record) bool {
	var local netip.Addr
	switch r.Direction {
	case flow.DirectionEgress:
		local = r.SrcIP
	case flow.DirectionIngress:
		local = r.DstIP
	default:
		return false
	}
	_, ok := a.hostAddresses[local.Unmap()]
	return ok
}

func (a *Agent) allows(r flow.Record) bool {
	addr := r.SrcIP.Unmap()
	if r.DstIP.Unmap().Is6() {
		addr = r.DstIP.Unmap()
	}
	if addr.Is4() && !a.capture.ipv4 {
		return false
	}
	if addr.Is6() && !a.capture.ipv6 {
		return false
	}
	if r.Protocol == 6 && !a.capture.tcp {
		return false
	}
	if r.Protocol == 17 && !a.capture.udp {
		return false
	}
	return true
}

func (a *Agent) SetCapture(ipv4, ipv6, tcp, udp bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.capture = captureSel{ipv4, ipv6, tcp, udp}
}

func (a *Agent) excluded(r flow.Record) bool {
	for _, prefix := range a.destinations {
		if prefix.Contains(r.DstIP) {
			return true
		}
	}
	sourceWorkload, destinationWorkload := false, false
	for _, prefix := range a.workloads {
		sourceWorkload = sourceWorkload || prefix.Contains(r.SrcIP)
		destinationWorkload = destinationWorkload || prefix.Contains(r.DstIP)
	}
	return sourceWorkload && destinationWorkload
}
