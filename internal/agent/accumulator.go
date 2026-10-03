package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/zbum/net-scouter/internal/flow"
	"github.com/zbum/net-scouter/internal/metrics"
	"github.com/zbum/net-scouter/internal/query"
	"github.com/zbum/net-scouter/internal/storage"
)

type rawBaseline struct {
	epoch    uint64
	counters flowCounters
}

type flowStore interface {
	Load() ([]flow.Record, error)
	Stats() (storage.Stats, error)
	Flush([]flow.Record, []storage.Key, storage.Retention) (storage.Stats, error)
}

// ConfigureExporter enables in-memory flow aggregation and cached metrics.
func (a *Agent) ConfigureExporter(exporter *metrics.Exporter, limit uint32) error {
	if exporter == nil || limit == 0 {
		return fmt.Errorf("metrics exporter and positive flow limit are required")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.mode != "" {
		return fmt.Errorf("agent mode already configured")
	}
	a.mode, a.metrics, a.metricsLimit = "exporter", exporter, limit
	return nil
}

// ConfigurePersistent loads prior records and enables periodic durable flushes.
func (a *Agent) ConfigurePersistent(store flowStore, path string, flushInterval time.Duration, retention storage.Retention) error {
	if store == nil || path == "" || flushInterval <= 0 {
		return fmt.Errorf("persistent storage and positive flush interval are required")
	}
	records, err := store.Load()
	if err != nil {
		return err
	}
	stats, err := store.Stats()
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.mode != "" {
		return fmt.Errorf("agent mode already configured")
	}
	for _, record := range records {
		key, err := storage.EncodeKey(record)
		if err != nil {
			return err
		}
		a.persistedKeys[key] = struct{}{}
		if a.excluded(record) {
			a.pendingDeletes[key] = struct{}{}
			continue
		}
		a.stored[key] = record
	}
	a.mode, a.store, a.storagePath, a.flushInterval, a.retention = "persistent", store, path, flushInterval, retention
	a.storageStats = stats
	if err := a.reconcileReturnPathsLocked(); err != nil {
		return err
	}
	a.boundStoredLocked()
	a.observedFrom, a.observedTo = observationWindow(a.currentFlowsLocked())
	return nil
}

func (a *Agent) runConfigured(ctx context.Context) error {
	if a.metrics != nil {
		if err := a.metrics.Start(); err != nil {
			return err
		}
		defer func() {
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = a.metrics.Shutdown(shutdown)
		}()
	}
	a.collectConfigured()
	collectTicker := time.NewTicker(a.interval)
	defer collectTicker.Stop()
	var flushTicker *time.Ticker
	var flushC <-chan time.Time
	if a.mode == "persistent" {
		flushTicker = time.NewTicker(a.flushInterval)
		defer flushTicker.Stop()
		flushC = flushTicker.C
	}
	for {
		select {
		case <-ctx.Done():
			a.collectConfigured()
			if a.mode == "persistent" {
				a.mu.Lock()
				err := a.flushLocked(time.Now())
				a.mu.Unlock()
				return err
			}
			return nil
		case <-collectTicker.C:
			a.collectConfigured()
		case <-flushC:
			a.mu.Lock()
			_ = a.flushLocked(time.Now())
			a.mu.Unlock()
		}
	}
}

func (a *Agent) collectConfigured() {
	a.mu.Lock()
	defer a.mu.Unlock()
	records, err := a.observeLocked()
	if err != nil {
		a.lastError = err.Error()
		if a.metrics != nil {
			a.metricsCollectedAt = time.Now()
			a.metrics.Publish(a.currentFlowsLocked(), metrics.Metadata{
				Success: false, CollectedAt: a.metricsCollectedAt, KernelMapEntries: uint64(a.mapEntries), KernelMapCapacity: uint64(a.maxFlows), ConnectionsEnabled: a.obs.ConnectionsEnabled,
			})
		}
		_ = query.WriteStatus(a.statusPath, a.statusLocked())
		return
	}
	if a.legacyStdout {
		if err := a.emitLegacyLocked(records); err != nil {
			a.lastError = err.Error()
		}
	}
	if a.metrics != nil {
		a.publishMetricsLocked()
	}
	_ = query.WriteStatus(a.statusPath, a.statusLocked())
}

func (a *Agent) emitLegacyLocked(records []flow.Record) error {
	a.generation++
	encoder := json.NewEncoder(a.output)
	for _, record := range records {
		identity := flowIdentity{record.SrcIP, record.DstIP, 0, record.DstPort, record.Protocol, record.Direction}
		current := flowCounters{record.Packets, record.Bytes, record.Connections, record.LastSeen}
		previous, exists := a.previous[identity]
		unchanged := exists && previous.counters == current && previous.generation+1 == a.generation
		a.previous[identity] = cacheEntry{current, a.generation}
		if !unchanged {
			if err := encoder.Encode(record); err != nil {
				return fmt.Errorf("encode flow: %w", err)
			}
		}
	}
	a.pruneCache()
	return nil
}

func (a *Agent) observeLocked() ([]flow.Record, error) {
	records, err := a.source.Snapshot()
	if err != nil {
		return nil, fmt.Errorf("snapshot flows: %w", err)
	}
	if err := a.ingestLocked(records); err != nil {
		return nil, err
	}
	a.mapEntries = len(records)
	a.lastSnapshotAt = time.Now()
	a.lastError = ""
	visible := a.currentFlowsLocked()
	a.observedFrom, a.observedTo = observationWindow(visible)
	return visible, nil
}

func (a *Agent) ingestLocked(snapshot []flow.Record) error {
	a.refreshDockerNetworks()
	if a.storageNeedsReload {
		if err := a.reloadCommittedLocked(); err != nil {
			return err
		}
	}
	active := make(map[flowIdentity]struct{}, len(snapshot))
	for _, record := range flow.ForACLRaw(snapshot) {
		if !a.allows(record) || !a.fromSelectedHostAddress(record) || a.excluded(record) {
			continue
		}
		identity := flowIdentity{record.SrcIP.Unmap(), record.DstIP.Unmap(), record.SrcPort, record.DstPort, record.Protocol, record.Direction}
		active[identity] = struct{}{}
		current := flowCounters{record.Packets, record.Bytes, record.Connections, record.LastSeen}
		previous, exists := a.baselines[identity]
		// A new BPF entry has a new monotonic first-seen epoch even if its
		// counters have already grown beyond those of an evicted entry.
		fresh := !exists || previous.epoch != record.EpochNS
		if record.Protocol == 6 && record.Connections == 0 {
			if exists && !fresh && previous.counters.connections > 0 {
				a.counterRegression = true
				continue
			}
			a.baselines[identity] = rawBaseline{record.EpochNS, current}
			continue
		}
		if record.Protocol == 6 && exists && previous.counters.connections == 0 {
			fresh = true
		}
		delta := record
		if !fresh {
			var decreased bool
			delta.Packets, decreased = highWaterDelta(record.Packets, previous.counters.packets)
			a.counterRegression = a.counterRegression || decreased
			delta.Bytes, decreased = highWaterDelta(record.Bytes, previous.counters.bytes)
			a.counterRegression = a.counterRegression || decreased
			delta.Connections, decreased = highWaterDelta(record.Connections, previous.counters.connections)
			a.counterRegression = a.counterRegression || decreased
			current.packets = max(current.packets, previous.counters.packets)
			current.bytes = max(current.bytes, previous.counters.bytes)
			current.connections = max(current.connections, previous.counters.connections)
		}
		a.baselines[identity] = rawBaseline{record.EpochNS, current}
		if delta.Packets == 0 && delta.Bytes == 0 && delta.Connections == 0 {
			continue
		}
		key, err := storage.EncodeKey(record)
		if err != nil {
			return fmt.Errorf("aggregate flow: %w", err)
		}
		accumulated, exists := a.stored[key]
		if !exists {
			accumulated = record
			accumulated.SrcIP = record.SrcIP.Unmap()
			accumulated.DstIP = record.DstIP.Unmap()
			accumulated.SrcPort = 0
			accumulated.Packets, accumulated.Bytes, accumulated.Connections = 0, 0, 0
		} else if accumulated.FirstSeen.IsZero() || (!record.FirstSeen.IsZero() && record.FirstSeen.Before(accumulated.FirstSeen)) {
			accumulated.FirstSeen = record.FirstSeen
		}
		if record.LastSeen.After(accumulated.LastSeen) {
			accumulated.LastSeen = record.LastSeen
		}
		accumulated.Packets += delta.Packets
		accumulated.Bytes += delta.Bytes
		accumulated.Connections += delta.Connections
		a.stored[key] = accumulated
		if a.mode == "persistent" {
			a.dirtyKeys[key] = struct{}{}
			delete(a.pendingDeletes, key)
		}
	}
	if err := a.reconcileReturnPathsLocked(); err != nil {
		return err
	}
	a.boundStoredLocked()
	if len(a.baselines) > a.cacheLimit {
		// Bounded baseline memory trades exactness for resource safety under
		// sustained kernel-map churn; surface that loss in status.
		a.counterRegression = true
		for key := range a.baselines {
			if _, current := active[key]; current {
				continue
			}
			delete(a.baselines, key)
			if len(a.baselines) <= a.cacheLimit {
				break
			}
		}
	}
	return nil
}

func (a *Agent) reconcileReturnPathsLocked() error {
	if len(a.stored) < 2 {
		return nil
	}
	records := make([]flow.Record, 0, len(a.stored))
	for _, record := range a.stored {
		records = append(records, record)
	}
	kept := make(map[storage.Key]struct{}, len(records))
	for _, record := range flow.ForACL(records) {
		key, err := storage.EncodeKey(record)
		if err != nil {
			return fmt.Errorf("select return paths: %w", err)
		}
		kept[key] = struct{}{}
	}
	for key := range a.stored {
		if _, ok := kept[key]; ok {
			continue
		}
		delete(a.stored, key)
		delete(a.dirtyKeys, key)
		if _, persisted := a.persistedKeys[key]; persisted {
			a.pendingDeletes[key] = struct{}{}
		}
	}
	return nil
}

func (a *Agent) boundStoredLocked() {
	limit := int(a.maxFlows)
	if a.mode == "persistent" && a.retention.MaxEntries > 0 {
		limit = a.retention.MaxEntries
	}
	if limit <= 0 || len(a.stored) <= limit {
		return
	}
	type candidate struct {
		key      storage.Key
		lastSeen time.Time
	}
	oldest := make([]candidate, 0, len(a.stored))
	for key, record := range a.stored {
		oldest = append(oldest, candidate{key, record.LastSeen})
	}
	slices.SortFunc(oldest, func(x, y candidate) int {
		if order := x.lastSeen.Compare(y.lastSeen); order != 0 {
			return order
		}
		return bytes.Compare(x.key[:], y.key[:])
	})
	for _, item := range oldest[:len(oldest)-limit] {
		delete(a.stored, item.key)
		delete(a.dirtyKeys, item.key)
		if a.mode == "persistent" {
			if _, persisted := a.persistedKeys[item.key]; persisted {
				a.pendingDeletes[item.key] = struct{}{}
			}
		}
		a.memoryEvictedTotal++
	}
	a.counterRegression = true
}

func highWaterDelta(current, previous uint64) (uint64, bool) {
	if current < previous {
		return 0, true
	}
	return current - previous, false
}

func (a *Agent) currentFlowsLocked() []flow.Record {
	records := make([]flow.Record, 0, len(a.stored))
	for _, record := range a.stored {
		if a.excluded(record) {
			continue
		}
		records = append(records, record)
	}
	return records
}

func (a *Agent) publishMetricsLocked() {
	records := a.currentFlowsLocked()
	a.metricsPublished = min(len(records), int(a.metricsLimit))
	a.metricsOmitted = len(records) - a.metricsPublished
	a.metricsCollectedAt = a.lastSnapshotAt
	a.metrics.Publish(records, metrics.Metadata{
		Success: true, CollectedAt: a.lastSnapshotAt, KernelMapEntries: uint64(a.mapEntries), KernelMapCapacity: uint64(a.maxFlows), ConnectionsEnabled: a.obs.ConnectionsEnabled,
	})
}

func (a *Agent) flushLocked(now time.Time) error {
	if a.store == nil {
		return nil
	}
	if a.storageNeedsReload {
		return a.reloadCommittedLocked()
	}
	records := make([]flow.Record, 0, len(a.dirtyKeys))
	for key := range a.dirtyKeys {
		if record, ok := a.stored[key]; ok && !a.excluded(record) {
			records = append(records, record)
		}
	}
	retention := a.retention
	retention.Now = now
	deletes := make([]storage.Key, 0, len(a.pendingDeletes))
	for key := range a.pendingDeletes {
		deletes = append(deletes, key)
	}
	stats, err := a.store.Flush(records, deletes, retention)
	if err != nil {
		a.storageError = err.Error()
		_ = query.WriteStatus(a.statusPath, a.statusLocked())
		return err
	}
	a.lastFlush = now
	a.storageStats = stats
	a.storageNeedsReload = true
	return a.reloadCommittedLocked()
}

func (a *Agent) reloadCommittedLocked() error {
	loaded, err := a.store.Load()
	if err != nil {
		a.storageError = err.Error()
		_ = query.WriteStatus(a.statusPath, a.statusLocked())
		return err
	}
	a.stored = make(map[storage.Key]flow.Record, len(loaded))
	clear(a.persistedKeys)
	for _, record := range loaded {
		key, err := storage.EncodeKey(record)
		if err != nil {
			return err
		}
		a.stored[key] = record
		a.persistedKeys[key] = struct{}{}
	}
	clear(a.pendingDeletes)
	clear(a.dirtyKeys)
	a.storageNeedsReload = false
	a.storageError = ""
	a.observedFrom, a.observedTo = observationWindow(a.currentFlowsLocked())
	_ = query.WriteStatus(a.statusPath, a.statusLocked())
	return nil
}

// Flush performs a durable flush and reports storage errors without losing memory state.
func (a *Agent) Flush() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.mode != "persistent" {
		return errors.New("persistent storage is not configured")
	}
	return a.flushLocked(time.Now())
}

// FilterHistorical returns loaded flow rows allowed by the current CIDR rules.
func (a *Agent) FilterHistorical(records []flow.Record) []flow.Record {
	a.mu.Lock()
	defer a.mu.Unlock()
	filtered := make([]flow.Record, 0, len(records))
	for _, record := range records {
		if !a.excluded(record) {
			filtered = append(filtered, record)
		}
	}
	return filtered
}

// FilterHistoricalRecords applies current CIDR exclusions to an offline store.
func FilterHistoricalRecords(records []flow.Record, destinations, workloads []string, ingress, egress DirectionExclusions) ([]flow.Record, error) {
	dest, err := parsePrefixes(destinations)
	if err != nil {
		return nil, err
	}
	work, err := parsePrefixes(workloads)
	if err != nil {
		return nil, err
	}
	a := &Agent{destinations: dest, workloads: work}
	a.dockerNetworks, err = DockerNetworks()
	if err != nil {
		return nil, fmt.Errorf("discover Docker networks: %w", err)
	}
	if err := a.SetDirectionalExclusions(ingress, egress); err != nil {
		return nil, err
	}
	return a.FilterHistorical(records), nil
}
