package metrics

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zbum/net-scouter/internal/flow"
)

func TestPublishRendersDeterministicPrometheusText(t *testing.T) {
	t.Parallel()
	when := time.Date(2026, 9, 26, 1, 2, 3, 500_000_000, time.UTC)
	exporter := New(":0", 0)
	exporter.Publish([]flow.Record{
		{SrcIP: addr("192.0.2.2"), DstIP: addr("203.0.113.2"), SrcPort: 50000, DstPort: 53, Protocol: 17, Direction: flow.DirectionEgress, FirstSeen: when, LastSeen: when, Packets: 2, Bytes: 20, Connections: 99},
		{SrcIP: addr("192.0.2.1"), DstIP: addr("203.0.113.1"), SrcPort: 40000, DstPort: 443, Protocol: 6, Direction: flow.DirectionEgress, FirstSeen: when.Add(-time.Minute), LastSeen: when, Packets: 3, Bytes: 30, Connections: 1},
	}, Metadata{Success: true, CollectedAt: when, KernelMapEntries: 2, KernelMapCapacity: 65536, ConnectionsEnabled: true})

	body := scrape(t, exporter, http.MethodGet, "/metrics").Body.String()
	want := `# HELP net_scouter_flow_packets_total Packets observed for a flow.
# TYPE net_scouter_flow_packets_total counter
net_scouter_flow_packets_total{src="192.0.2.1",dst="203.0.113.1",protocol="tcp",direction="egress",dst_port="443"} 3
net_scouter_flow_packets_total{src="192.0.2.2",dst="203.0.113.2",protocol="udp",direction="egress",dst_port="53"} 2
`
	if !strings.HasPrefix(body, want) {
		t.Fatalf("metrics prefix:\n%s\nwant:\n%s", body, want)
	}
	assertContains(t, body,
		"net_scouter_flow_connections_total{src=\"192.0.2.1\",dst=\"203.0.113.1\",protocol=\"tcp\",direction=\"egress\",dst_port=\"443\"} 1\n",
		"net_scouter_flow_first_seen_timestamp_seconds{src=\"192.0.2.1\",dst=\"203.0.113.1\",protocol=\"tcp\",direction=\"egress\",dst_port=\"443\"} 1.7903844635e+09\n",
		"net_scouter_collector_success 1\n",
		"net_scouter_collector_last_collection_timestamp_seconds 1.7903845235e+09\n",
		"net_scouter_collector_kernel_map_entries 2\n",
		"net_scouter_collector_kernel_map_capacity 65536\n",
		"net_scouter_collector_connections_enabled 1\n",
		"net_scouter_collector_exported_flows 2\n",
		"net_scouter_collector_omitted_flows 0\n",
	)
	if strings.Contains(body, `protocol="udp",direction="egress",dst_port="53"} 99`) {
		t.Fatal("UDP flow exported a connection count")
	}
	if strings.Contains(body, "src_port") {
		t.Fatal("source port must not be a metric label")
	}
}

func TestPublishMergesDuplicateLabels(t *testing.T) {
	t.Parallel()
	early := time.Unix(100, 0)
	late := time.Unix(200, 0)
	exporter := New(":0", 0)
	exporter.Publish([]flow.Record{
		record("192.0.2.1", "203.0.113.1", 443, early, 2, 20, 1),
		record("192.0.2.1", "203.0.113.1", 443, late, 3, 30, 2),
	}, Metadata{})
	body := scrape(t, exporter, http.MethodGet, "/metrics").Body.String()
	if got := strings.Count(body, "net_scouter_flow_packets_total{"); got != 1 {
		t.Fatalf("packet sample count=%d, want 1", got)
	}
	assertContains(t, body,
		`dst_port="443"} 5`+"\n",
		"net_scouter_flow_connections_total{src=\"192.0.2.1\",dst=\"203.0.113.1\",protocol=\"tcp\",direction=\"egress\",dst_port=\"443\"} 3\n",
		`net_scouter_flow_first_seen_timestamp_seconds{src="192.0.2.1",dst="203.0.113.1",protocol="tcp",direction="egress",dst_port="443"} 100`+"\n",
		`net_scouter_flow_last_seen_timestamp_seconds{src="192.0.2.1",dst="203.0.113.1",protocol="tcp",direction="egress",dst_port="443"} 200`+"\n",
	)
}

func TestPublishLimitsByMostRecentThenOrdersByLabels(t *testing.T) {
	t.Parallel()
	exporter := New(":0", 2)
	exporter.Publish([]flow.Record{
		record("192.0.2.3", "203.0.113.3", 443, time.Unix(100, 0), 1, 1, 1),
		record("192.0.2.2", "203.0.113.2", 443, time.Unix(300, 0), 1, 1, 1),
		record("192.0.2.1", "203.0.113.1", 443, time.Unix(300, 0), 1, 1, 1),
	}, Metadata{})
	body := scrape(t, exporter, http.MethodGet, "/metrics").Body.String()
	if strings.Contains(body, `src="192.0.2.3"`) {
		t.Fatal("oldest flow was not omitted")
	}
	first := strings.Index(body, `src="192.0.2.1"`)
	second := strings.Index(body, `src="192.0.2.2"`)
	if first < 0 || second < 0 || first >= second {
		t.Fatalf("selected flows are not label ordered:\n%s", body)
	}
	assertContains(t, body, "net_scouter_collector_exported_flows 2\n", "net_scouter_collector_omitted_flows 1\n")
}

func TestEscapePrometheusLabel(t *testing.T) {
	t.Parallel()
	if got, want := escape("a\\b\"c\nd"), `a\\b\"c\nd`; got != want {
		t.Fatalf("escape=%q, want %q", got, want)
	}
}

func TestServeHTTPMethodsAndPaths(t *testing.T) {
	t.Parallel()
	exporter := New(":0", 0)

	get := scrape(t, exporter, http.MethodGet, "/metrics")
	if get.Code != http.StatusOK || get.Header().Get("Content-Type") != contentType || get.Body.Len() == 0 {
		t.Fatalf("GET status=%d content-type=%q body=%q", get.Code, get.Header().Get("Content-Type"), get.Body.String())
	}
	head := scrape(t, exporter, http.MethodHead, "/metrics")
	if head.Code != http.StatusOK || head.Body.Len() != 0 {
		t.Fatalf("HEAD status=%d body=%q", head.Code, head.Body.String())
	}
	post := scrape(t, exporter, http.MethodPost, "/metrics")
	if post.Code != http.StatusMethodNotAllowed || post.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("POST status=%d allow=%q", post.Code, post.Header().Get("Allow"))
	}
	if got := scrape(t, exporter, http.MethodGet, "/other").Code; got != http.StatusNotFound {
		t.Fatalf("other path status=%d", got)
	}
}

func TestRepeatedScrapesUsePublishedCache(t *testing.T) {
	t.Parallel()
	records := []flow.Record{record("192.0.2.1", "203.0.113.1", 443, time.Unix(100, 0), 4, 40, 1)}
	exporter := New(":0", 0)
	exporter.Publish(records, Metadata{Success: true})
	first := scrape(t, exporter, http.MethodGet, "/metrics").Body.String()
	records[0].Packets = 999
	second := scrape(t, exporter, http.MethodGet, "/metrics").Body.String()
	if first != second || strings.Contains(second, "} 999\n") {
		t.Fatal("scrape response was recomputed from caller-owned records")
	}
}

func TestLifecycleAndListenFailure(t *testing.T) {
	failing := New("bad-address", 0)
	failing.listenFn = func(string, string) (net.Listener, error) {
		return nil, errors.New("address unavailable")
	}
	if err := failing.Start(); err == nil {
		t.Fatal("Start succeeded after listen failure")
	}

	listener := newBlockingListener()
	exporter := New("test-address", 0)
	exporter.listenFn = func(network, address string) (net.Listener, error) {
		if network != "tcp" || address != "test-address" {
			t.Fatalf("listen args=(%q, %q)", network, address)
		}
		return listener, nil
	}
	if err := exporter.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if exporter.Addr() == "" {
		t.Fatal("Addr is empty after Start")
	}
	if err := exporter.Start(); err == nil {
		t.Fatal("second Start succeeded")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := exporter.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if exporter.Addr() != "" {
		t.Fatal("Addr is not empty after Shutdown")
	}
	if err := exporter.Shutdown(ctx); err != nil {
		t.Fatalf("second Shutdown: %v", err)
	}
}

type blockingListener struct {
	closed chan struct{}
	once   sync.Once
}

func newBlockingListener() *blockingListener {
	return &blockingListener{closed: make(chan struct{})}
}

func (l *blockingListener) Accept() (net.Conn, error) {
	<-l.closed
	return nil, net.ErrClosed
}

func (l *blockingListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *blockingListener) Addr() net.Addr { return testAddr("test-address") }

type testAddr string

func (a testAddr) Network() string { return "tcp" }
func (a testAddr) String() string  { return string(a) }

func scrape(t *testing.T, exporter *Exporter, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	exporter.ServeHTTP(recorder, httptest.NewRequest(method, path, nil))
	return recorder
}

func record(src, dst string, port uint16, seen time.Time, packets, bytes, connections uint64) flow.Record {
	return flow.Record{SrcIP: addr(src), DstIP: addr(dst), SrcPort: 50000, DstPort: port, Protocol: 6, Direction: flow.DirectionEgress, FirstSeen: seen, LastSeen: seen, Packets: packets, Bytes: bytes, Connections: connections}
}

func addr(value string) netip.Addr { return netip.MustParseAddr(value) }

func assertContains(t *testing.T, value string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(value, want) {
			t.Errorf("output does not contain %q:\n%s", want, value)
		}
	}
}
