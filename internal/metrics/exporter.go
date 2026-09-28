// Package metrics exposes cached flow snapshots in the Prometheus text format.
package metrics

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zbum/net-scouter/internal/flow"
)

const contentType = "text/plain; version=0.0.4; charset=utf-8"

// Metadata describes the collector state associated with a published snapshot.
type Metadata struct {
	Success            bool
	CollectedAt        time.Time
	KernelMapEntries   uint64
	KernelMapCapacity  uint64
	ConnectionsEnabled bool
}

// Exporter serves snapshots rendered during Publish. HTTP scrapes never invoke
// the collector or access its backing store.
type Exporter struct {
	listen   string
	maxFlows uint32
	cached   atomic.Pointer[response]
	listenFn func(network, address string) (net.Listener, error)

	mu       sync.Mutex
	listener net.Listener
	server   *http.Server
}

type response struct{ body []byte }

// New constructs an exporter. A maxFlows value of zero does not limit flows.
func New(listen string, maxFlows uint32) *Exporter {
	e := &Exporter{listen: listen, maxFlows: maxFlows, listenFn: net.Listen}
	e.cached.Store(&response{body: render(nil, Metadata{}, maxFlows)})
	return e
}

// Publish atomically replaces the cached response without retaining records.
func (e *Exporter) Publish(records []flow.Record, metadata Metadata) {
	e.cached.Store(&response{body: render(records, metadata, e.maxFlows)})
}

// Start begins serving HTTP. It returns after the listen socket is ready.
func (e *Exporter) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.server != nil {
		return errors.New("metrics exporter already started")
	}

	listener, err := e.listenFn("tcp", e.listen)
	if err != nil {
		return fmt.Errorf("listen for metrics: %w", err)
	}
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", e)
	mux.Handle("HEAD /metrics", e)
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	e.listener = listener
	e.server = server
	go func() {
		_ = server.Serve(listener)
	}()
	return nil
}

// Addr returns the bound listener address, or an empty string before Start.
func (e *Exporter) Addr() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.listener == nil {
		return ""
	}
	return e.listener.Addr().String()
}

// Shutdown gracefully stops the HTTP server.
func (e *Exporter) Shutdown(ctx context.Context) error {
	e.mu.Lock()
	server := e.server
	e.mu.Unlock()
	if server == nil {
		return nil
	}
	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown metrics exporter: %w", err)
	}
	e.mu.Lock()
	e.server = nil
	e.listener = nil
	e.mu.Unlock()
	return nil
}

// ServeHTTP writes only the already-rendered response.
func (e *Exporter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/metrics" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(e.cached.Load().body)
	}
}

type labelKey struct {
	src, dst  string
	protocol  string
	direction string
	dstPort   uint16
}

type metricFlow struct {
	key                     labelKey
	firstSeen, lastSeen     time.Time
	packets, bytes, connNum uint64
}

func render(records []flow.Record, metadata Metadata, maxFlows uint32) []byte {
	merged := make(map[labelKey]metricFlow, len(records))
	for _, record := range records {
		protocol := protocolName(record.Protocol)
		if protocol == "" {
			continue
		}
		key := labelKey{record.SrcIP.String(), record.DstIP.String(), protocol, record.Direction.String(), record.DstPort}
		current, ok := merged[key]
		if !ok {
			current = metricFlow{key: key, firstSeen: record.FirstSeen}
		} else if current.firstSeen.IsZero() || (!record.FirstSeen.IsZero() && record.FirstSeen.Before(current.firstSeen)) {
			current.firstSeen = record.FirstSeen
		}
		if record.LastSeen.After(current.lastSeen) {
			current.lastSeen = record.LastSeen
		}
		current.packets += record.Packets
		current.bytes += record.Bytes
		if protocol == "tcp" {
			current.connNum += record.Connections
		}
		merged[key] = current
	}

	flows := make([]metricFlow, 0, len(merged))
	for _, item := range merged {
		flows = append(flows, item)
	}
	slices.SortFunc(flows, func(a, b metricFlow) int {
		if c := b.lastSeen.Compare(a.lastSeen); c != 0 {
			return c
		}
		return compareKey(a.key, b.key)
	})
	omitted := 0
	if maxFlows > 0 && uint64(len(flows)) > uint64(maxFlows) {
		omitted = len(flows) - int(maxFlows)
		flows = flows[:maxFlows]
	}
	slices.SortFunc(flows, func(a, b metricFlow) int { return compareKey(a.key, b.key) })

	var b bytes.Buffer
	header(&b, "net_scouter_flow_packets_total", "Packets observed for a flow.", "counter")
	for _, item := range flows {
		sample(&b, "net_scouter_flow_packets_total", item.key, item.packets)
	}
	header(&b, "net_scouter_flow_bytes_total", "Bytes observed for a flow.", "counter")
	for _, item := range flows {
		sample(&b, "net_scouter_flow_bytes_total", item.key, item.bytes)
	}
	header(&b, "net_scouter_flow_connections_total", "Established TCP connections observed for a flow.", "counter")
	for _, item := range flows {
		if item.key.protocol == "tcp" {
			sample(&b, "net_scouter_flow_connections_total", item.key, item.connNum)
		}
	}
	header(&b, "net_scouter_flow_first_seen_timestamp_seconds", "Unix timestamp when a flow was first observed.", "gauge")
	for _, item := range flows {
		timeSample(&b, "net_scouter_flow_first_seen_timestamp_seconds", item.key, item.firstSeen)
	}
	header(&b, "net_scouter_flow_last_seen_timestamp_seconds", "Unix timestamp when a flow was last observed.", "gauge")
	for _, item := range flows {
		timeSample(&b, "net_scouter_flow_last_seen_timestamp_seconds", item.key, item.lastSeen)
	}
	collector(&b, "net_scouter_collector_success", "Whether the latest collection succeeded.", boolFloat(metadata.Success))
	collector(&b, "net_scouter_collector_last_collection_timestamp_seconds", "Unix timestamp of the latest collection attempt.", timestamp(metadata.CollectedAt))
	collector(&b, "net_scouter_collector_kernel_map_entries", "Entries in the kernel flow map at the latest collection.", float64(metadata.KernelMapEntries))
	collector(&b, "net_scouter_collector_kernel_map_capacity", "Configured capacity of the kernel flow map.", float64(metadata.KernelMapCapacity))
	collector(&b, "net_scouter_collector_connections_enabled", "Whether TCP established-connection collection is enabled.", boolFloat(metadata.ConnectionsEnabled))
	collector(&b, "net_scouter_collector_exported_flows", "Flows exported in the cached response.", float64(len(flows)))
	collector(&b, "net_scouter_collector_omitted_flows", "Flows omitted by the export limit.", float64(omitted))
	return b.Bytes()
}

func protocolName(protocol uint8) string {
	switch protocol {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return ""
	}
}

func compareKey(a, b labelKey) int {
	return cmp.Or(
		strings.Compare(a.src, b.src),
		strings.Compare(a.dst, b.dst),
		strings.Compare(a.protocol, b.protocol),
		strings.Compare(a.direction, b.direction),
		cmp.Compare(a.dstPort, b.dstPort),
	)
}

func header(b *bytes.Buffer, name, help, metricType string) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, metricType)
}

func labels(key labelKey) string {
	return fmt.Sprintf(`src="%s",dst="%s",protocol="%s",direction="%s",dst_port="%d"`,
		escape(key.src), escape(key.dst), escape(key.protocol), escape(key.direction), key.dstPort)
}

func sample(b *bytes.Buffer, name string, key labelKey, value uint64) {
	fmt.Fprintf(b, "%s{%s} %s\n", name, labels(key), strconv.FormatUint(value, 10))
}

func timeSample(b *bytes.Buffer, name string, key labelKey, value time.Time) {
	fmt.Fprintf(b, "%s{%s} %s\n", name, labels(key), formatFloat(timestamp(value)))
}

func collector(b *bytes.Buffer, name, help string, value float64) {
	header(b, name, help, "gauge")
	fmt.Fprintf(b, "%s %s\n", name, formatFloat(value))
}

func escape(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, "\n", `\n`)
	return strings.ReplaceAll(value, `"`, `\"`)
}

func boolFloat(value bool) float64 {
	if value {
		return 1
	}
	return 0
}

func timestamp(value time.Time) float64 {
	if value.IsZero() {
		return 0
	}
	return float64(value.UnixNano()) / float64(time.Second)
}

func formatFloat(value float64) string {
	return strconv.FormatFloat(value, 'g', -1, 64)
}
