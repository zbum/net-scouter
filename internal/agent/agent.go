package agent

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"time"

	"github.com/example/net-scouter/internal/flow"
)

type Snapshotter interface{ Snapshot() ([]flow.Record, error) }

type Agent struct {
	source       Snapshotter
	output       io.Writer
	interval     time.Duration
	destinations []netip.Prefix
	workloads    []netip.Prefix
	previous     map[flowIdentity]cacheEntry
	generation   uint64
	cacheLimit   int
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

func New(source Snapshotter, output io.Writer, interval time.Duration, maxFlows uint32, destinationCIDRs, workloadCIDRs []string) (*Agent, error) {
	dest, err := parsePrefixes(destinationCIDRs)
	if err != nil {
		return nil, fmt.Errorf("destination exclusions: %w", err)
	}
	work, err := parsePrefixes(workloadCIDRs)
	if err != nil {
		return nil, fmt.Errorf("workload exclusions: %w", err)
	}
	return &Agent{source: source, output: output, interval: interval, destinations: dest, workloads: work, previous: make(map[flowIdentity]cacheEntry), cacheLimit: int(maxFlows) * 3}, nil
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
	records, err := a.source.Snapshot()
	if err != nil {
		return fmt.Errorf("snapshot flows: %w", err)
	}
	a.generation++
	encoder := json.NewEncoder(a.output)
	for _, record := range records {
		if a.excluded(record) {
			continue
		}
		identity := flowIdentity{record.SrcIP, record.DstIP, record.SrcPort, record.DstPort, record.Protocol, record.Direction}
		current := flowCounters{record.Packets, record.Bytes, record.Connections, record.LastSeen}
		previous, exists := a.previous[identity]
		unchanged := exists && previous.counters == current && previous.generation+1 == a.generation
		a.previous[identity] = cacheEntry{current, a.generation}
		if unchanged {
			continue
		}
		if err := encoder.Encode(record); err != nil {
			return fmt.Errorf("encode flow: %w", err)
		}
	}
	a.pruneCache()
	return nil
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
