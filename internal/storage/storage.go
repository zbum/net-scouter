// Package storage provides crash-consistent persistence for aggregated flows.
package storage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/zbum/net-scouter/internal/flow"
	bolt "go.etcd.io/bbolt"
)

const (
	schemaVersion  uint32 = 1
	recordVersion  byte   = 1
	keySize               = 36
	recordSize            = 48
	defaultTimeout        = time.Second
)

var (
	metaBucket     = []byte("meta")
	flowsBucket    = []byte("flows")
	lastSeenBucket = []byte("last_seen")
	schemaKey      = []byte("schema_version")
	expiredKey     = []byte("expired_total")
	evictedKey     = []byte("evicted_total")
	maxBytesKey    = []byte("max_bytes")
)

// ErrUnsupportedSchema means the database was created with another schema.
var ErrUnsupportedSchema = errors.New("unsupported storage schema")

// ErrCorrupt means persisted data cannot be decoded safely.
var ErrCorrupt = errors.New("corrupt storage data")

// Key is the canonical ACL flow identity. Source ports are intentionally absent.
type Key [keySize]byte

// Options controls opening and informational disk thresholds.
type Options struct {
	ReadOnly bool
	Timeout  time.Duration
	MaxBytes int64
}

// Retention controls pruning performed atomically with a Flush.
type Retention struct {
	Now         time.Time
	InactiveTTL time.Duration
	MaxEntries  int
	MaxBytes    int64
}

// Stats reports durable entry and retention counters. MaxBytes is an
// informational threshold; OverMaxBytes never causes record deletion.
type Stats struct {
	Entries      int
	FileBytes    int64
	MaxBytes     int64
	OverMaxBytes bool
	ExpiredTotal uint64
	EvictedTotal uint64
}

// Store wraps one bbolt database.
type Store struct {
	db       *bolt.DB
	path     string
	readOnly bool
}

// Open opens or creates a durable store. Writable databases are created with
// owner-only permissions.
func Open(path string, options Options) (*Store, error) {
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{
		ReadOnly:   options.ReadOnly,
		Timeout:    timeout,
		NoSync:     false,
		NoGrowSync: false,
	})
	if err != nil {
		return nil, fmt.Errorf("open flow store: %w", err)
	}
	store := &Store{db: db, path: path, readOnly: options.ReadOnly}
	if err := store.initialize(options.MaxBytes); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

// OpenReadOnly opens an existing store without taking a writer lock.
func OpenReadOnly(path string) (*Store, error) {
	return Open(path, Options{ReadOnly: true})
}

func (s *Store) initialize(maxBytes int64) error {
	if s.readOnly {
		return s.db.View(validateSchema)
	}
	if err := os.Chmod(s.path, 0o600); err != nil {
		return fmt.Errorf("secure flow store: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		meta := tx.Bucket(metaBucket)
		flows := tx.Bucket(flowsBucket)
		index := tx.Bucket(lastSeenBucket)
		if meta != nil || flows != nil || index != nil {
			if meta == nil || flows == nil || index == nil {
				return fmt.Errorf("%w: required bucket missing", ErrCorrupt)
			}
			if err := validateSchema(tx); err != nil {
				return err
			}
		} else {
			var err error
			if meta, err = tx.CreateBucket(metaBucket); err != nil {
				return fmt.Errorf("create meta bucket: %w", err)
			}
			if _, err = tx.CreateBucket(flowsBucket); err != nil {
				return fmt.Errorf("create flows bucket: %w", err)
			}
			if _, err = tx.CreateBucket(lastSeenBucket); err != nil {
				return fmt.Errorf("create last-seen bucket: %w", err)
			}
			if err = putUint32(meta, schemaKey, schemaVersion); err != nil {
				return err
			}
		}
		if maxBytes > 0 {
			return putUint64(meta, maxBytesKey, uint64(maxBytes))
		}
		return nil
	})
}

func validateSchema(tx *bolt.Tx) error {
	meta := tx.Bucket(metaBucket)
	if meta == nil {
		return fmt.Errorf("%w: meta bucket missing", ErrCorrupt)
	}
	raw := meta.Get(schemaKey)
	if len(raw) != 4 {
		return fmt.Errorf("%w: invalid schema metadata", ErrCorrupt)
	}
	version := binary.BigEndian.Uint32(raw)
	if version != schemaVersion {
		return fmt.Errorf("%w: got %d, want %d", ErrUnsupportedSchema, version, schemaVersion)
	}
	if tx.Bucket(flowsBucket) == nil || tx.Bucket(lastSeenBucket) == nil {
		return fmt.Errorf("%w: required bucket missing", ErrCorrupt)
	}
	return nil
}

// EncodeKey creates the fixed-width canonical identity for a flow.
func EncodeKey(record flow.Record) (Key, error) {
	var key Key
	if !record.SrcIP.IsValid() || !record.DstIP.IsValid() {
		return key, fmt.Errorf("encode flow key: invalid IP address")
	}
	src := record.SrcIP.Unmap().As16()
	dst := record.DstIP.Unmap().As16()
	copy(key[0:16], src[:])
	copy(key[16:32], dst[:])
	key[32] = record.Protocol
	key[33] = byte(record.Direction)
	binary.BigEndian.PutUint16(key[34:36], record.DstPort)
	return key, nil
}

// DecodeKey decodes a canonical identity. SourcePort is always zero.
func DecodeKey(key Key) (flow.Record, error) {
	src, ok := netip.AddrFromSlice(key[0:16])
	if !ok {
		return flow.Record{}, fmt.Errorf("%w: invalid source address", ErrCorrupt)
	}
	dst, ok := netip.AddrFromSlice(key[16:32])
	if !ok {
		return flow.Record{}, fmt.Errorf("%w: invalid destination address", ErrCorrupt)
	}
	direction := flow.Direction(key[33])
	if direction != flow.DirectionIngress && direction != flow.DirectionEgress {
		return flow.Record{}, fmt.Errorf("%w: invalid direction %d", ErrCorrupt, direction)
	}
	return flow.Record{
		SrcIP:     src.Unmap(),
		DstIP:     dst.Unmap(),
		Protocol:  key[32],
		Direction: direction,
		DstPort:   binary.BigEndian.Uint16(key[34:36]),
	}, nil
}

func encodeRecord(record flow.Record) [recordSize]byte {
	var value [recordSize]byte
	value[0] = recordVersion
	binary.BigEndian.PutUint64(value[8:16], uint64(timeNano(record.FirstSeen)))
	binary.BigEndian.PutUint64(value[16:24], uint64(timeNano(record.LastSeen)))
	binary.BigEndian.PutUint64(value[24:32], record.Packets)
	binary.BigEndian.PutUint64(value[32:40], record.Bytes)
	binary.BigEndian.PutUint64(value[40:48], record.Connections)
	return value
}

func decodeRecord(key Key, value []byte) (flow.Record, error) {
	if len(value) != recordSize || value[0] != recordVersion {
		return flow.Record{}, fmt.Errorf("%w: invalid record encoding", ErrCorrupt)
	}
	record, err := DecodeKey(key)
	if err != nil {
		return flow.Record{}, err
	}
	record.FirstSeen = nanoTime(int64(binary.BigEndian.Uint64(value[8:16])))
	record.LastSeen = nanoTime(int64(binary.BigEndian.Uint64(value[16:24])))
	record.Packets = binary.BigEndian.Uint64(value[24:32])
	record.Bytes = binary.BigEndian.Uint64(value[32:40])
	record.Connections = binary.BigEndian.Uint64(value[40:48])
	return record, nil
}

func timeNano(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.UnixNano()
}

func nanoTime(value int64) time.Time {
	if value == 0 {
		return time.Time{}
	}
	return time.Unix(0, value).UTC()
}

// Load returns all records, failing without mutation if any record is corrupt.
func (s *Store) Load() ([]flow.Record, error) {
	var records []flow.Record
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := validateSchema(tx); err != nil {
			return err
		}
		bucket := tx.Bucket(flowsBucket)
		records = make([]flow.Record, 0, bucket.Stats().KeyN)
		return bucket.ForEach(func(rawKey, value []byte) error {
			if len(rawKey) != keySize {
				return fmt.Errorf("%w: invalid flow key length %d", ErrCorrupt, len(rawKey))
			}
			var key Key
			copy(key[:], rawKey)
			record, err := decodeRecord(key, value)
			if err != nil {
				return err
			}
			records = append(records, record)
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("load flows: %w", err)
	}
	return records, nil
}

// Flush atomically stores absolute counter values, deletes explicit keys,
// updates retention metadata, and applies deterministic retention pruning.
func (s *Store) Flush(upserts []flow.Record, deletes []Key, retention Retention) (Stats, error) {
	if s.readOnly {
		return Stats{}, errors.New("flush flows: store is read-only")
	}
	var stats Stats
	err := s.db.Update(func(tx *bolt.Tx) error {
		if err := validateSchema(tx); err != nil {
			return err
		}
		flows := tx.Bucket(flowsBucket)
		index := tx.Bucket(lastSeenBucket)
		meta := tx.Bucket(metaBucket)
		for _, key := range deletes {
			if err := deleteRecord(flows, index, key); err != nil {
				return err
			}
		}
		for _, record := range upserts {
			key, err := EncodeKey(record)
			if err != nil {
				return err
			}
			if previous := flows.Get(key[:]); previous != nil {
				decoded, err := decodeRecord(key, previous)
				if err != nil {
					return err
				}
				if err := index.Delete(indexKey(decoded.LastSeen, key)); err != nil {
					return fmt.Errorf("delete previous index: %w", err)
				}
			}
			value := encodeRecord(record)
			if err := flows.Put(key[:], value[:]); err != nil {
				return fmt.Errorf("put flow: %w", err)
			}
			if err := index.Put(indexKey(record.LastSeen, key), nil); err != nil {
				return fmt.Errorf("put last-seen index: %w", err)
			}
		}
		expired, evicted, err := prune(flows, index, retention)
		if err != nil {
			return err
		}
		if retention.MaxBytes > 0 {
			if err := putUint64(meta, maxBytesKey, uint64(retention.MaxBytes)); err != nil {
				return err
			}
		}
		if err := addUint64(meta, expiredKey, expired); err != nil {
			return err
		}
		if err := addUint64(meta, evictedKey, evicted); err != nil {
			return err
		}
		stats = transactionStats(flows, meta)
		return nil
	})
	if err != nil {
		return Stats{}, fmt.Errorf("flush flows: %w", err)
	}
	return s.withFileStats(stats)
}

// UpsertBatch stores absolute values without applying retention.
func (s *Store) UpsertBatch(records []flow.Record) (Stats, error) {
	return s.Flush(records, nil, Retention{})
}

// Delete atomically removes canonical flow identities.
func (s *Store) Delete(keys []Key) (Stats, error) {
	return s.Flush(nil, keys, Retention{})
}

func deleteRecord(flows, index *bolt.Bucket, key Key) error {
	value := flows.Get(key[:])
	if value == nil {
		return nil
	}
	record, err := decodeRecord(key, value)
	if err != nil {
		return err
	}
	if err := index.Delete(indexKey(record.LastSeen, key)); err != nil {
		return fmt.Errorf("delete last-seen index: %w", err)
	}
	if err := flows.Delete(key[:]); err != nil {
		return fmt.Errorf("delete flow: %w", err)
	}
	return nil
}

func indexKey(lastSeen time.Time, key Key) []byte {
	result := make([]byte, 8+keySize)
	ordered := uint64(timeNano(lastSeen)) ^ (uint64(1) << 63)
	binary.BigEndian.PutUint64(result[:8], ordered)
	copy(result[8:], key[:])
	return result
}

func prune(flows, index *bolt.Bucket, retention Retention) (uint64, uint64, error) {
	var expired, evicted uint64
	entries := bucketCount(flows)
	if retention.InactiveTTL > 0 {
		now := retention.Now
		if now.IsZero() {
			now = time.Now()
		}
		cutoff := now.Add(-retention.InactiveTTL)
		cursor := index.Cursor()
		for raw, _ := cursor.First(); raw != nil; raw, _ = cursor.First() {
			if len(raw) != 8+keySize {
				return 0, 0, fmt.Errorf("%w: invalid last-seen index key", ErrCorrupt)
			}
			nanos := int64(binary.BigEndian.Uint64(raw[:8]) ^ (uint64(1) << 63))
			if !nanoTime(nanos).Before(cutoff) {
				break
			}
			var key Key
			copy(key[:], raw[8:])
			if err := validateIndexedRecord(flows, raw, key); err != nil {
				return 0, 0, err
			}
			if err := flows.Delete(key[:]); err != nil {
				return 0, 0, err
			}
			if err := cursor.Delete(); err != nil {
				return 0, 0, err
			}
			entries--
			expired++
		}
	}
	if retention.MaxEntries > 0 {
		cursor := index.Cursor()
		for entries > retention.MaxEntries {
			raw, _ := cursor.First()
			if len(raw) != 8+keySize {
				return 0, 0, fmt.Errorf("%w: invalid last-seen index key", ErrCorrupt)
			}
			var key Key
			copy(key[:], raw[8:])
			if err := validateIndexedRecord(flows, raw, key); err != nil {
				return 0, 0, err
			}
			if err := flows.Delete(key[:]); err != nil {
				return 0, 0, err
			}
			if err := cursor.Delete(); err != nil {
				return 0, 0, err
			}
			entries--
			evicted++
		}
	}
	return expired, evicted, nil
}

func validateIndexedRecord(flows *bolt.Bucket, rawIndex []byte, key Key) error {
	value := flows.Get(key[:])
	if value == nil {
		return fmt.Errorf("%w: index references missing flow", ErrCorrupt)
	}
	record, err := decodeRecord(key, value)
	if err != nil {
		return err
	}
	if !bytes.Equal(indexKey(record.LastSeen, key), rawIndex) {
		return fmt.Errorf("%w: last-seen index does not match flow", ErrCorrupt)
	}
	return nil
}

// Stats returns current metadata and the physical database size.
func (s *Store) Stats() (Stats, error) {
	var stats Stats
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := validateSchema(tx); err != nil {
			return err
		}
		stats = transactionStats(tx.Bucket(flowsBucket), tx.Bucket(metaBucket))
		return nil
	})
	if err != nil {
		return Stats{}, fmt.Errorf("read storage stats: %w", err)
	}
	return s.withFileStats(stats)
}

func transactionStats(flows, meta *bolt.Bucket) Stats {
	maxBytes := int64(readUint64(meta.Get(maxBytesKey)))
	return Stats{
		Entries:      bucketCount(flows),
		MaxBytes:     maxBytes,
		ExpiredTotal: readUint64(meta.Get(expiredKey)),
		EvictedTotal: readUint64(meta.Get(evictedKey)),
	}
}

func bucketCount(bucket *bolt.Bucket) int {
	count := 0
	cursor := bucket.Cursor()
	for key, _ := cursor.First(); key != nil; key, _ = cursor.Next() {
		count++
	}
	return count
}

func (s *Store) withFileStats(stats Stats) (Stats, error) {
	info, err := os.Stat(s.path)
	if err != nil {
		return Stats{}, fmt.Errorf("stat flow store: %w", err)
	}
	stats.FileBytes = info.Size()
	stats.OverMaxBytes = stats.MaxBytes > 0 && stats.FileBytes > stats.MaxBytes
	return stats, nil
}

func readUint64(raw []byte) uint64 {
	if len(raw) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(raw)
}

func addUint64(bucket *bolt.Bucket, key []byte, delta uint64) error {
	if delta == 0 {
		return nil
	}
	return putUint64(bucket, key, readUint64(bucket.Get(key))+delta)
}

func putUint64(bucket *bolt.Bucket, key []byte, value uint64) error {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], value)
	return bucket.Put(key, raw[:])
}

func putUint32(bucket *bolt.Bucket, key []byte, value uint32) error {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], value)
	return bucket.Put(key, raw[:])
}

// Close flushes and closes the database.
func (s *Store) Close() error {
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("close flow store: %w", err)
	}
	return nil
}
