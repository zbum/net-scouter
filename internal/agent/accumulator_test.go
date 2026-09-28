package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/zbum/net-scouter/internal/flow"
	"github.com/zbum/net-scouter/internal/metrics"
	"github.com/zbum/net-scouter/internal/storage"
)

func configuredAgent(t *testing.T, source *fakeSnapshotter) *Agent {
	t.Helper()
	a, err := New(source, &bytes.Buffer{}, time.Hour, 10, nil, nil, []netip.Addr{netip.MustParseAddr("10.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	a.SetRuntime([]string{"eth0"}, true, "5.15", "")
	if err := a.ConfigureExporter(metrics.New("127.0.0.1:0", 10), 10); err != nil {
		t.Fatal(err)
	}
	return a
}

func testRecord(epoch, packets, bytes, connections uint64) flow.Record {
	when := time.Date(2026, 9, 24, 1, 0, 0, 0, time.UTC)
	return flow.Record{
		SrcIP: netip.MustParseAddr("10.0.0.1"), DstIP: netip.MustParseAddr("192.0.2.5"),
		SrcPort: 40000, DstPort: 443, Protocol: 6, Direction: flow.DirectionEgress,
		FirstSeen: when, LastSeen: when.Add(time.Minute), EpochNS: epoch,
		Packets: packets, Bytes: bytes, Connections: connections,
	}
}

func TestKernelEpochIsAbsentFromFlowJSON(t *testing.T) {
	t.Parallel()
	body, err := json.Marshal(testRecord(123, 1, 2, 1))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("Epoch")) || bytes.Contains(body, []byte("epoch")) {
		t.Fatalf("internal epoch leaked: %s", body)
	}
}

func TestAccumulatorCountsDeltaBeforeSourcePortCollapse(t *testing.T) {
	t.Parallel()
	source := &fakeSnapshotter{records: []flow.Record{testRecord(1, 5, 50, 1)}}
	second := testRecord(2, 3, 30, 1)
	second.SrcPort = 40001
	source.records = append(source.records, second)
	a := configuredAgent(t, source)
	if st := a.Status(); st.Mode != "exporter" || st.DurableStorage != "disabled" || st.Storage.Path != "" {
		t.Fatalf("exporter mode status = %+v", st)
	}
	check := func(wantPackets, wantConnections uint64) {
		t.Helper()
		flows, err := a.Flows()
		if err != nil {
			t.Fatal(err)
		}
		if len(flows.Records) != 1 || flows.Records[0].Packets != wantPackets || *flows.Records[0].Connections != wantConnections {
			t.Fatalf("flows = %+v, want packets=%d connections=%d", flows.Records, wantPackets, wantConnections)
		}
	}
	check(8, 2)
	check(8, 2)
	_ = a.Status()
	check(8, 2)
	source.records[0].Packets, source.records[0].Bytes, source.records[0].Connections = 8, 80, 2
	check(11, 3)
	// A fresh kernel map entry can already have counters above its predecessor.
	source.records[0].EpochNS = 3
	source.records[0].Packets, source.records[0].Bytes, source.records[0].Connections = 20, 200, 4
	check(31, 7)
}

func TestAccumulatorCounterDecreaseUsesHighWater(t *testing.T) {
	t.Parallel()
	source := &fakeSnapshotter{records: []flow.Record{testRecord(1, 10, 100, 3)}}
	a := configuredAgent(t, source)
	if _, err := a.Flows(); err != nil {
		t.Fatal(err)
	}
	source.records[0].Packets, source.records[0].Bytes, source.records[0].Connections = 2, 20, 1
	flows, err := a.Flows()
	if err != nil {
		t.Fatal(err)
	}
	if flows.Records[0].Packets != 10 || *flows.Records[0].Connections != 3 || !a.Status().Map.PossibleLoss {
		t.Fatalf("counter decrease = %+v", flows.Records)
	}
	source.records[0].Packets, source.records[0].Bytes, source.records[0].Connections = 12, 120, 4
	flows, err = a.Flows()
	if err != nil {
		t.Fatal(err)
	}
	if flows.Records[0].Packets != 12 || *flows.Records[0].Connections != 4 {
		t.Fatalf("high-water recovery = %+v", flows.Records)
	}
}

func TestFlowAttemptsKeepsPacketOnlyTCPSnapshotOutOfAggregate(t *testing.T) {
	t.Parallel()
	source := &fakeSnapshotter{records: []flow.Record{testRecord(1, 5, 50, 0)}}
	a := configuredAgent(t, source)
	defaultFlows, err := a.Flows()
	if err != nil {
		t.Fatal(err)
	}
	if len(defaultFlows.Records) != 0 {
		t.Fatalf("unestablished TCP leaked into aggregate: %+v", defaultFlows.Records)
	}
	attempts, err := a.FlowAttempts()
	if err != nil {
		t.Fatal(err)
	}
	if len(attempts.Records) != 1 || attempts.Records[0].Packets != 5 {
		t.Fatalf("attempts = %+v", attempts.Records)
	}
	source.records[0].Connections = 1
	defaultFlows, err = a.Flows()
	if err != nil {
		t.Fatal(err)
	}
	if len(defaultFlows.Records) != 1 || defaultFlows.Records[0].Packets != 5 || *defaultFlows.Records[0].Connections != 1 {
		t.Fatalf("established flow = %+v", defaultFlows.Records)
	}
}

func TestPersistentRestartMergesHistoryAndKeepsOldHostAddress(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "flows.db")
	store, err := storage.Open(path, storage.Options{})
	if err != nil {
		t.Fatal(err)
	}
	source := &fakeSnapshotter{records: []flow.Record{testRecord(1, 5, 50, 1)}}
	a, err := New(source, &bytes.Buffer{}, time.Hour, 10, nil, nil, []netip.Addr{netip.MustParseAddr("10.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	a.SetRuntime([]string{"eth0"}, true, "5.15", "")
	retention := storage.Retention{InactiveTTL: 365 * 24 * time.Hour, MaxEntries: 10, MaxBytes: 1 << 20}
	if err := a.ConfigurePersistent(store, path, time.Minute, retention); err != nil {
		t.Fatal(err)
	}
	if st := a.Status(); st.Mode != "persistent" || st.DurableStorage != "ready" || st.Storage.Path != path || st.Storage.Schema != 1 || st.Exporter.Listen != "" {
		t.Fatalf("persistent mode status = %+v", st)
	}
	if _, err := a.Flows(); err != nil {
		t.Fatal(err)
	}
	if err := a.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = storage.Open(path, storage.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	// The server IP changed. Stored rows remain readable, while new capture
	// follows the current host address.
	source.records = nil
	b, err := New(source, &bytes.Buffer{}, time.Hour, 10, nil, nil, []netip.Addr{netip.MustParseAddr("10.0.0.2")})
	if err != nil {
		t.Fatal(err)
	}
	b.SetRuntime([]string{"eth0"}, false, "", "tracepoint unavailable")
	if err := b.ConfigurePersistent(store, path, time.Minute, retention); err != nil {
		t.Fatal(err)
	}
	flows, err := b.Flows()
	if err != nil {
		t.Fatal(err)
	}
	if len(flows.Records) != 1 || flows.Records[0].Packets != 5 || *flows.Records[0].Connections != 1 || !flows.ConnectionsAvailable || !flows.HistoricalConnections {
		t.Fatalf("historical flows = %+v", flows)
	}
	newRecord := testRecord(2, 7, 70, 1)
	newRecord.SrcIP = netip.MustParseAddr("10.0.0.2")
	source.records = []flow.Record{newRecord}
	flows, err = b.Flows()
	if err != nil {
		t.Fatal(err)
	}
	if len(flows.Records) != 2 {
		t.Fatalf("merged historical and current flows = %+v", flows.Records)
	}
}

func TestPersistentRestartAddsNewKernelEpochToSameACLRow(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "flows.db")
	store, err := storage.Open(path, storage.Options{})
	if err != nil {
		t.Fatal(err)
	}
	host := netip.MustParseAddr("10.0.0.1")
	retention := storage.Retention{InactiveTTL: 365 * 24 * time.Hour, MaxEntries: 10}
	source := &fakeSnapshotter{records: []flow.Record{testRecord(1, 5, 50, 1)}}
	newAgent := func() *Agent {
		t.Helper()
		a, err := New(source, &bytes.Buffer{}, time.Hour, 10, nil, nil, []netip.Addr{host})
		if err != nil {
			t.Fatal(err)
		}
		a.SetRuntime([]string{"eth0"}, true, "5.15", "")
		if err := a.ConfigurePersistent(store, path, time.Minute, retention); err != nil {
			t.Fatal(err)
		}
		return a
	}
	a := newAgent()
	if _, err := a.Flows(); err != nil {
		t.Fatal(err)
	}
	if err := a.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = storage.Open(path, storage.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	source.records[0] = testRecord(2, 7, 70, 2)
	b := newAgent()
	flows, err := b.Flows()
	if err != nil {
		t.Fatal(err)
	}
	if len(flows.Records) != 1 || flows.Records[0].Packets != 12 || *flows.Records[0].Connections != 3 {
		t.Fatalf("merged flow = %+v", flows.Records)
	}
	if err := b.Flush(); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 || loaded[0].Packets != 12 || loaded[0].Connections != 3 {
		t.Fatalf("durable merged flow = %+v", loaded)
	}
}

type failingStore struct {
	records []flow.Record
	fails   int
	flushes int
}

type interruptedStore struct {
	store    *storage.Store
	fail     bool
	failLoad bool
}

func (s *interruptedStore) Load() ([]flow.Record, error) {
	if s.failLoad {
		return nil, errors.New("read unavailable")
	}
	return s.store.Load()
}
func (s *interruptedStore) Stats() (storage.Stats, error) { return s.store.Stats() }
func (s *interruptedStore) Flush(upserts []flow.Record, deletes []storage.Key, retention storage.Retention) (storage.Stats, error) {
	if s.fail {
		return storage.Stats{}, errors.New("disk unavailable")
	}
	return s.store.Flush(upserts, deletes, retention)
}

func TestPersistentFlushFailureBoundsMemoryAndRecoversDeletes(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "flows.db")
	db, err := storage.Open(path, storage.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	base := testRecord(1, 1, 10, 1)
	base.DstIP = netip.MustParseAddr("192.0.2.1")
	base.LastSeen = base.FirstSeen.Add(time.Minute)
	other := base
	other.DstIP = netip.MustParseAddr("192.0.2.2")
	if _, err := db.UpsertBatch([]flow.Record{other, base}); err != nil {
		t.Fatal(err)
	}
	source := &fakeSnapshotter{}
	a, err := New(source, &bytes.Buffer{}, time.Hour, 10, nil, nil, []netip.Addr{netip.MustParseAddr("10.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	a.SetRuntime([]string{"eth0"}, true, "5.15", "")
	store := &interruptedStore{store: db, fail: true}
	retention := storage.Retention{InactiveTTL: 365 * 24 * time.Hour, MaxEntries: 2}
	if err := a.ConfigurePersistent(store, path, time.Minute, retention); err != nil {
		t.Fatal(err)
	}
	for i := 3; i < 23; i++ {
		record := base
		record.DstIP = netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})
		record.EpochNS = uint64(i)
		record.LastSeen = base.LastSeen.Add(time.Duration(i) * time.Minute)
		source.records = []flow.Record{record}
		if _, err := a.Flows(); err != nil {
			t.Fatal(err)
		}
		if err := a.Flush(); err == nil {
			t.Fatal("expected flush failure")
		}
		if len(a.stored) > 2 || len(a.dirtyKeys) > 2 || len(a.pendingDeletes) > 2 {
			t.Fatalf("unbounded memory at %d: stored=%d dirty=%d deletes=%d", i, len(a.stored), len(a.dirtyKeys), len(a.pendingDeletes))
		}
	}
	st := a.Status()
	if st.MemoryEvictedTotal != 20 || !st.Map.PossibleLoss || st.DurableStorage != "degraded" || len(a.pendingDeletes) != 2 {
		t.Fatalf("loss state = %+v, pending deletes = %d", st, len(a.pendingDeletes))
	}
	if a.stored[storageKey(t, base)].DstIP.IsValid() {
		t.Fatal("oldest persisted row remained in memory")
	}
	store.fail = false
	if err := a.Flush(); err != nil {
		t.Fatal(err)
	}
	loaded, err := db.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 2 || loaded[0].DstIP != netip.MustParseAddr("192.0.2.21") || loaded[1].DstIP != netip.MustParseAddr("192.0.2.22") {
		t.Fatalf("recovered durable rows = %+v", loaded)
	}
	if len(a.pendingDeletes) != 0 || len(a.dirtyKeys) != 0 || a.Status().DurableStorage != "ready" || a.Status().MemoryEvictedTotal != 20 {
		t.Fatalf("recovered state = %+v", a.Status())
	}
}

func storageKey(t *testing.T, record flow.Record) storage.Key {
	t.Helper()
	key, err := storage.EncodeKey(record)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestPersistentMemoryEvictsOldestThenCanonicalKeyOnTie(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "flows.db")
	db, err := storage.Open(path, storage.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	base := testRecord(1, 1, 10, 1)
	base.DstIP = netip.MustParseAddr("192.0.2.1")
	second := base
	second.DstIP = netip.MustParseAddr("192.0.2.2")
	third := base
	third.DstIP = netip.MustParseAddr("192.0.2.3")
	if _, err := db.UpsertBatch([]flow.Record{second, base}); err != nil {
		t.Fatal(err)
	}
	source := &fakeSnapshotter{records: []flow.Record{third}}
	a, err := New(source, &bytes.Buffer{}, time.Hour, 10, nil, nil, []netip.Addr{netip.MustParseAddr("10.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	a.SetRuntime([]string{"eth0"}, true, "5.15", "")
	if err := a.ConfigurePersistent(&interruptedStore{store: db, fail: true}, path, time.Minute, storage.Retention{MaxEntries: 2}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Flows(); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.stored[storageKey(t, base)]; ok {
		t.Fatal("smallest canonical key was not evicted on LastSeen tie")
	}
	if _, ok := a.pendingDeletes[storageKey(t, base)]; !ok {
		t.Fatal("persisted eviction was not scheduled for deletion")
	}
	if a.Status().MemoryEvictedTotal != 1 {
		t.Fatalf("memory evictions = %d", a.Status().MemoryEvictedTotal)
	}
}

func TestPersistentReloadFailureAfterCommitPausesIngestUntilRecovery(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "flows.db")
	db, err := storage.Open(path, storage.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	source := &fakeSnapshotter{records: []flow.Record{testRecord(1, 1, 10, 1)}}
	a, err := New(source, &bytes.Buffer{}, time.Hour, 2, nil, nil, []netip.Addr{netip.MustParseAddr("10.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	a.SetRuntime([]string{"eth0"}, true, "5.15", "")
	store := &interruptedStore{store: db}
	if err := a.ConfigurePersistent(store, path, time.Minute, storage.Retention{MaxEntries: 2}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Flows(); err != nil {
		t.Fatal(err)
	}
	store.failLoad = true
	if err := a.Flush(); err == nil || !a.storageNeedsReload {
		t.Fatalf("committed flush with failed reload = %v, reload=%t", err, a.storageNeedsReload)
	}
	source.records[0].DstIP = netip.MustParseAddr("192.0.2.6")
	if _, err := a.Flows(); err == nil || len(a.stored) != 1 {
		t.Fatalf("ingest continued during failed reload: %v, stored=%d", err, len(a.stored))
	}
	store.failLoad = false
	if _, err := a.Flows(); err != nil {
		t.Fatal(err)
	}
	if err := a.Flush(); err != nil {
		t.Fatal(err)
	}
	if a.storageNeedsReload || len(a.stored) != 2 || len(a.persistedKeys) != 2 {
		t.Fatalf("reload recovery: reload=%t, stored=%d, persisted=%d", a.storageNeedsReload, len(a.stored), len(a.persistedKeys))
	}
}

func TestStoredUDPResponseIsRemovedWhenServiceFlowArrivesLater(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "flows.db")
	db, err := storage.Open(path, storage.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	response := testRecord(1, 2, 20, 0)
	response.Protocol = 17
	response.Direction = flow.DirectionIngress
	response.SrcIP = netip.MustParseAddr("192.0.2.5")
	response.DstIP = netip.MustParseAddr("10.0.0.1")
	response.DstPort = 40000
	request := response
	request.EpochNS = 2
	request.Direction = flow.DirectionEgress
	request.SrcIP, request.DstIP = response.DstIP, response.SrcIP
	request.DstPort = 53
	source := &fakeSnapshotter{records: []flow.Record{response}}
	a, err := New(source, &bytes.Buffer{}, time.Hour, 10, nil, nil, []netip.Addr{netip.MustParseAddr("10.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	a.SetRuntime([]string{"eth0"}, true, "5.15", "")
	if err := a.ConfigurePersistent(db, path, time.Minute, storage.Retention{MaxEntries: 10}); err != nil {
		t.Fatal(err)
	}
	if flows, err := a.Flows(); err != nil || len(flows.Records) != 1 || flows.Records[0].DstPort != 40000 {
		t.Fatalf("response-only flows = %+v, %v", flows, err)
	}
	if err := a.Flush(); err != nil {
		t.Fatal(err)
	}
	source.records = []flow.Record{request}
	flows, err := a.Flows()
	if err != nil {
		t.Fatal(err)
	}
	if len(flows.Records) != 1 || flows.Records[0].DstPort != 53 || a.Status().MemoryEvictedTotal != 0 {
		t.Fatalf("service flows after response cleanup = %+v, status = %+v", flows.Records, a.Status())
	}
	if _, ok := a.pendingDeletes[storageKey(t, response)]; !ok {
		t.Fatal("persisted response was not scheduled for deletion")
	}
	if err := a.Flush(); err != nil {
		t.Fatal(err)
	}
	loaded, err := db.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 || loaded[0].DstPort != 53 {
		t.Fatalf("durable rows after cleanup = %+v", loaded)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := storage.Open(path, storage.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	loaded, err = reopened.Load()
	if err != nil || len(loaded) != 1 || loaded[0].DstPort != 53 {
		t.Fatalf("rows after restart = %+v, %v", loaded, err)
	}
}

func TestStoredHighPortFlowRemainsWithoutOppositeServicePort(t *testing.T) {
	t.Parallel()
	high := testRecord(1, 2, 20, 0)
	high.Protocol = 17
	high.Direction = flow.DirectionIngress
	high.SrcIP = netip.MustParseAddr("192.0.2.5")
	high.DstIP = netip.MustParseAddr("10.0.0.1")
	high.DstPort = 40000
	opposite := high
	opposite.EpochNS = 2
	opposite.Direction = flow.DirectionEgress
	opposite.SrcIP, opposite.DstIP = high.DstIP, high.SrcIP
	opposite.DstPort = 40001
	source := &fakeSnapshotter{records: []flow.Record{high}}
	a := configuredAgent(t, source)
	if flows, err := a.Flows(); err != nil || len(flows.Records) != 1 {
		t.Fatalf("initial high-port flow = %+v, %v", flows, err)
	}
	source.records = []flow.Record{opposite}
	flows, err := a.Flows()
	if err != nil {
		t.Fatal(err)
	}
	if len(flows.Records) != 2 || a.Status().MemoryEvictedTotal != 0 {
		t.Fatalf("legitimate high-port flows = %+v, status = %+v", flows.Records, a.Status())
	}
}

func (s *failingStore) Load() ([]flow.Record, error) {
	return append([]flow.Record(nil), s.records...), nil
}
func (s *failingStore) Stats() (storage.Stats, error) { return storage.Stats{}, nil }
func (s *failingStore) Flush(records []flow.Record, _ []storage.Key, _ storage.Retention) (storage.Stats, error) {
	s.flushes++
	if s.fails > 0 {
		s.fails--
		return storage.Stats{}, errors.New("disk unavailable")
	}
	s.records = append([]flow.Record(nil), records...)
	return storage.Stats{Entries: len(records)}, nil
}

func TestPersistentFlushFailureRetainsAndRetries(t *testing.T) {
	t.Parallel()
	source := &fakeSnapshotter{records: []flow.Record{testRecord(1, 5, 50, 1)}}
	a, err := New(source, &bytes.Buffer{}, time.Hour, 10, nil, nil, []netip.Addr{netip.MustParseAddr("10.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	a.SetRuntime([]string{"eth0"}, true, "5.15", "")
	store := &failingStore{fails: 1}
	if err := a.ConfigurePersistent(store, "/tmp/test-flows.db", time.Minute, storage.Retention{}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Flows(); err != nil {
		t.Fatal(err)
	}
	if err := a.Flush(); err == nil || a.Status().DurableStorage != "degraded" {
		t.Fatalf("flush failure = %v, status = %+v", err, a.Status())
	}
	if err := a.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(store.records) != 1 || store.records[0].Packets != 5 || a.Status().DurableStorage != "ready" {
		t.Fatalf("retry records = %+v, status = %+v", store.records, a.Status())
	}
}

func TestPersistentRunFinalFlush(t *testing.T) {
	t.Parallel()
	source := &fakeSnapshotter{records: []flow.Record{testRecord(1, 5, 50, 1)}}
	a, err := New(source, &bytes.Buffer{}, time.Hour, 10, nil, nil, []netip.Addr{netip.MustParseAddr("10.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	a.SetRuntime([]string{"eth0"}, true, "5.15", "")
	store := &failingStore{}
	if err := a.ConfigurePersistent(store, "/tmp/test-flows.db", time.Hour, storage.Retention{}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := a.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if store.flushes != 1 || len(store.records) != 1 || store.records[0].Packets != 5 {
		t.Fatalf("final flushes = %d, records = %+v", store.flushes, store.records)
	}
}

func TestExporterRunServesPublishedMetricsWithoutStorage(t *testing.T) {
	t.Parallel()
	source := &fakeSnapshotter{records: []flow.Record{testRecord(1, 5, 50, 1)}}
	a := configuredAgent(t, source)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("run: %v", err)
		}
	}()
	client := &http.Client{Timeout: time.Second}
	deadline := time.After(3 * time.Second)
	for {
		addr := a.metrics.Addr()
		if addr != "" {
			response, err := client.Get("http://" + addr + "/metrics")
			if err == nil {
				body, readErr := io.ReadAll(response.Body)
				response.Body.Close()
				if readErr == nil && response.StatusCode == http.StatusOK && bytes.Contains(body, []byte("net_scouter_flow_connections_total{src=\"10.0.0.1\"")) {
					if a.store != nil {
						t.Fatal("exporter opened a storage backend")
					}
					return
				}
			}
		}
		select {
		case <-deadline:
			t.Fatal("metrics endpoint did not publish the collected flow")
		case <-time.After(10 * time.Millisecond):
		}
	}
}
