package storage

import (
	"bytes"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/zbum/net-scouter/internal/flow"
	bolt "go.etcd.io/bbolt"
)

func TestKeyRoundTripIPv4AndIPv6OmitsSourcePort(t *testing.T) {
	t.Parallel()

	tests := []flow.Record{
		{
			SrcIP: netip.MustParseAddr("192.0.2.10"), DstIP: netip.MustParseAddr("198.51.100.20"),
			SrcPort: 49152, DstPort: 443, Protocol: 6, Direction: flow.DirectionEgress,
		},
		{
			SrcIP: netip.MustParseAddr("2001:db8::10"), DstIP: netip.MustParseAddr("2001:db8::20"),
			SrcPort: 53000, DstPort: 53, Protocol: 17, Direction: flow.DirectionIngress,
		},
	}
	for _, want := range tests {
		key, err := EncodeKey(want)
		if err != nil {
			t.Fatalf("EncodeKey(%+v): %v", want, err)
		}
		got, err := DecodeKey(key)
		if err != nil {
			t.Fatalf("DecodeKey(%+v): %v", key, err)
		}
		if got.SrcIP != want.SrcIP || got.DstIP != want.DstIP || got.DstPort != want.DstPort || got.Protocol != want.Protocol || got.Direction != want.Direction {
			t.Fatalf("decoded key = %+v, want identity from %+v", got, want)
		}
		if got.SrcPort != 0 {
			t.Fatalf("decoded source port = %d, want 0", got.SrcPort)
		}

		other := want
		other.SrcPort++
		otherKey, err := EncodeKey(other)
		if err != nil {
			t.Fatalf("EncodeKey(other): %v", err)
		}
		if key != otherKey {
			t.Fatal("source port changed canonical key")
		}
	}
}

func TestStorePersistsVersionedRecordAcrossRestart(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "flows.db")
	want := testRecord("192.0.2.1", "198.51.100.1", 443, time.Date(2026, 9, 26, 1, 2, 3, 4, time.UTC))

	store := openTestStore(t, path, Options{})
	if _, err := store.UpsertBatch([]flow.Record{want}); err != nil {
		t.Fatalf("UpsertBatch: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened := openTestStore(t, path, Options{})
	defer closeTestStore(t, reopened)
	got, err := reopened.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != 1 || !recordsEqual(got[0], want) {
		t.Fatalf("Load = %+v, want %+v", got, want)
	}
}

func TestUpsertBatchOverwritesAbsoluteValuesIdempotently(t *testing.T) {
	t.Parallel()
	store := openTestStore(t, filepath.Join(t.TempDir(), "flows.db"), Options{})
	defer closeTestStore(t, store)

	record := testRecord("192.0.2.2", "198.51.100.2", 80, time.Now().UTC())
	record.Packets, record.Bytes, record.Connections = 7, 700, 3
	for range 2 {
		if _, err := store.UpsertBatch([]flow.Record{record}); err != nil {
			t.Fatalf("UpsertBatch: %v", err)
		}
	}
	record.Packets, record.Bytes, record.Connections = 2, 200, 1
	if _, err := store.UpsertBatch([]flow.Record{record}); err != nil {
		t.Fatalf("absolute overwrite: %v", err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != 1 || got[0].Packets != 2 || got[0].Bytes != 200 || got[0].Connections != 1 {
		t.Fatalf("Load = %+v, want one absolute overwrite", got)
	}
}

func TestFlushPrunesInactiveAndOldestDeterministically(t *testing.T) {
	t.Parallel()
	store := openTestStore(t, filepath.Join(t.TempDir(), "flows.db"), Options{})
	defer closeTestStore(t, store)

	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	expired := testRecord("192.0.2.1", "203.0.113.1", 443, now.Add(-25*time.Hour))
	tiedA := testRecord("192.0.2.2", "203.0.113.1", 443, now.Add(-time.Hour))
	tiedB := testRecord("192.0.2.3", "203.0.113.1", 443, now.Add(-time.Hour))
	tiedC := testRecord("192.0.2.4", "203.0.113.1", 443, now.Add(-time.Hour))
	stats, err := store.Flush([]flow.Record{tiedC, expired, tiedB, tiedA}, nil, Retention{
		Now: now, InactiveTTL: 24 * time.Hour, MaxEntries: 2,
	})
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if stats.Entries != 2 || stats.ExpiredTotal != 1 || stats.EvictedTotal != 1 {
		t.Fatalf("Stats = %+v", stats)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	slices.SortFunc(got, func(a, b flow.Record) int { return a.SrcIP.Compare(b.SrcIP) })
	if len(got) != 2 || got[0].SrcIP != tiedB.SrcIP || got[1].SrcIP != tiedC.SrcIP {
		t.Fatalf("remaining records = %+v, want deterministic eviction of %s", got, tiedA.SrcIP)
	}
}

func TestFlushPrunesEveryConsecutiveExpiredRecord(t *testing.T) {
	t.Parallel()
	store := openTestStore(t, filepath.Join(t.TempDir(), "flows.db"), Options{})
	defer closeTestStore(t, store)

	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	expiredAt := now.Add(-25 * time.Hour)
	cutoff := now.Add(-24 * time.Hour)
	rows := []flow.Record{
		testRecord("192.0.2.3", "203.0.113.1", 443, expiredAt),
		testRecord("192.0.2.1", "203.0.113.1", 443, expiredAt),
		testRecord("192.0.2.2", "203.0.113.1", 443, expiredAt),
		testRecord("192.0.2.4", "203.0.113.1", 443, cutoff),
		testRecord("192.0.2.5", "203.0.113.1", 443, now),
	}
	stats, err := store.Flush(rows, nil, Retention{Now: now, InactiveTTL: 24 * time.Hour, MaxEntries: 2})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Entries != 2 || stats.ExpiredTotal != 3 || stats.EvictedTotal != 0 {
		t.Fatalf("stats = %+v, want 3 expired and 2 active", stats)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].SrcIP != rows[3].SrcIP || got[1].SrcIP != rows[4].SrcIP {
		t.Fatalf("retained rows = %+v", got)
	}
}

func TestMaxBytesIsInformationalOnly(t *testing.T) {
	t.Parallel()
	store := openTestStore(t, filepath.Join(t.TempDir(), "flows.db"), Options{MaxBytes: 1})
	defer closeTestStore(t, store)

	record := testRecord("192.0.2.5", "203.0.113.5", 443, time.Now().UTC())
	stats, err := store.UpsertBatch([]flow.Record{record})
	if err != nil {
		t.Fatalf("UpsertBatch: %v", err)
	}
	if !stats.OverMaxBytes || stats.MaxBytes != 1 || stats.Entries != 1 {
		t.Fatalf("Stats = %+v, want informational threshold with retained entry", stats)
	}
}

func TestUnsupportedSchemaIsRejectedAndPreserved(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "flows.db")
	store := openTestStore(t, path, Options{})
	if err := store.db.Update(func(tx *bolt.Tx) error {
		return putUint32(tx.Bucket(metaBucket), schemaKey, schemaVersion+1)
	}); err != nil {
		t.Fatalf("write unsupported schema: %v", err)
	}
	closeTestStore(t, store)

	_, err := Open(path, Options{})
	if !errors.Is(err, ErrUnsupportedSchema) {
		t.Fatalf("Open error = %v, want ErrUnsupportedSchema", err)
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	if err != nil {
		t.Fatalf("inspect database: %v", err)
	}
	defer func() { _ = db.Close() }()
	if err := db.View(func(tx *bolt.Tx) error {
		got := binaryUint32(tx.Bucket(metaBucket).Get(schemaKey))
		if got != schemaVersion+1 {
			t.Fatalf("schema changed to %d", got)
		}
		return nil
	}); err != nil {
		t.Fatalf("inspect schema: %v", err)
	}
}

func TestCorruptRecordIsRejectedAndPreserved(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "flows.db")
	store := openTestStore(t, path, Options{})
	record := testRecord("192.0.2.6", "203.0.113.6", 443, time.Now().UTC())
	key, err := EncodeKey(record)
	if err != nil {
		t.Fatalf("EncodeKey: %v", err)
	}
	corrupt := []byte{recordVersion, 1, 2}
	if err := store.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(flowsBucket).Put(key[:], corrupt); err != nil {
			return err
		}
		return tx.Bucket(lastSeenBucket).Put(indexKey(record.LastSeen, key), nil)
	}); err != nil {
		t.Fatalf("insert corrupt record: %v", err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Load error = %v, want ErrCorrupt", err)
	}
	if _, err := store.Flush(nil, nil, Retention{
		Now:         record.LastSeen.Add(2 * time.Hour),
		InactiveTTL: time.Hour,
	}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("pruning corrupt record error = %v, want ErrCorrupt", err)
	}
	if err := store.db.View(func(tx *bolt.Tx) error {
		if got := tx.Bucket(flowsBucket).Get(key[:]); !bytes.Equal(got, corrupt) {
			t.Fatalf("corrupt value changed to %x", got)
		}
		return nil
	}); err != nil {
		t.Fatalf("inspect corrupt record: %v", err)
	}
	closeTestStore(t, store)
}

func TestStoreCreatesOwnerOnlyFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions are unavailable")
	}
	path := filepath.Join(t.TempDir(), "flows.db")
	store := openTestStore(t, path, Options{})
	defer closeTestStore(t, store)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %o, want 600", got)
	}
}

func TestReadOnlyOfflineLoadAndWriterLockTimeout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flows.db")
	store := openTestStore(t, path, Options{})
	record := testRecord("192.0.2.7", "203.0.113.7", 22, time.Now().UTC())
	if _, err := store.UpsertBatch([]flow.Record{record}); err != nil {
		t.Fatalf("UpsertBatch: %v", err)
	}
	if _, err := Open(path, Options{Timeout: 25 * time.Millisecond}); !errors.Is(err, bolt.ErrTimeout) {
		t.Fatalf("second writer error = %v, want bolt.ErrTimeout", err)
	}
	closeTestStore(t, store)

	readOnly, err := OpenReadOnly(path)
	if err != nil {
		t.Fatalf("OpenReadOnly: %v", err)
	}
	defer closeTestStore(t, readOnly)
	got, err := readOnly.Load()
	if err != nil || len(got) != 1 || !recordsEqual(got[0], record) {
		t.Fatalf("read-only Load = %+v, %v", got, err)
	}
	if _, err := readOnly.UpsertBatch([]flow.Record{record}); err == nil {
		t.Fatal("read-only UpsertBatch succeeded")
	}
}

func testRecord(src, dst string, port uint16, lastSeen time.Time) flow.Record {
	return flow.Record{
		SrcIP: netip.MustParseAddr(src), DstIP: netip.MustParseAddr(dst),
		SrcPort: 50000, DstPort: port, Protocol: 6, Direction: flow.DirectionEgress,
		FirstSeen: lastSeen.Add(-time.Minute), LastSeen: lastSeen,
		Packets: 10, Bytes: 1000, Connections: 2,
	}
}

func recordsEqual(a, b flow.Record) bool {
	return a.SrcIP == b.SrcIP && a.DstIP == b.DstIP && a.SrcPort == 0 &&
		a.DstPort == b.DstPort && a.Protocol == b.Protocol && a.Direction == b.Direction &&
		a.FirstSeen.Equal(b.FirstSeen) && a.LastSeen.Equal(b.LastSeen) &&
		a.Packets == b.Packets && a.Bytes == b.Bytes && a.Connections == b.Connections
}

func openTestStore(t *testing.T, path string, options Options) *Store {
	t.Helper()
	store, err := Open(path, options)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return store
}

func closeTestStore(t *testing.T, store *Store) {
	t.Helper()
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func binaryUint32(raw []byte) uint32 {
	if len(raw) != 4 {
		return 0
	}
	return uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
}
