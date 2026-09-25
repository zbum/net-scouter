package agent

import (
	"bytes"
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/example/net-scouter/internal/flow"
)

type fakeSnapshotter struct{ records []flow.Record }

func (f fakeSnapshotter) Snapshot() ([]flow.Record, error) { return f.records, nil }

func TestExportDropsDisabledIPv6(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	a, err := New(fakeSnapshotter{records: []flow.Record{
		{SrcIP: netip.MustParseAddr("10.0.0.1"), DstIP: netip.MustParseAddr("10.0.0.2"), DstPort: 443, Protocol: 6, Direction: flow.DirectionEgress, Connections: 1},
		{SrcIP: netip.MustParseAddr("2001:db8::1"), DstIP: netip.MustParseAddr("2001:db8::2"), DstPort: 443, Protocol: 6, Direction: flow.DirectionEgress, Connections: 1},
	}}, &output, time.Hour, 10, nil, nil, []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("2001:db8::1")})
	if err != nil {
		t.Fatal(err)
	}
	a.SetRuntime([]string{"eth0"}, true, "5.15", "")
	a.SetCapture(true, false, true, true)
	if err := a.export(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "2001:db8") || !strings.Contains(output.String(), "10.0.0.2") {
		t.Fatalf("output: %s", output.String())
	}
}

func TestRunFiltersDestinationAndSameHostWorkload(t *testing.T) {
	t.Parallel()
	records := []flow.Record{
		{SrcIP: netip.MustParseAddr("10.0.0.1"), DstIP: netip.MustParseAddr("192.0.2.1"), Protocol: 6, Direction: flow.DirectionEgress, Connections: 1},
		{SrcIP: netip.MustParseAddr("10.0.0.1"), DstIP: netip.MustParseAddr("10.0.0.2"), Protocol: 6, Direction: flow.DirectionEgress, Connections: 1},
		{SrcIP: netip.MustParseAddr("10.0.0.1"), DstIP: netip.MustParseAddr("203.0.113.2"), Protocol: 6, Direction: flow.DirectionEgress, Connections: 1},
	}
	var output bytes.Buffer
	a, err := New(fakeSnapshotter{records}, &output, time.Hour, 10, []string{"192.0.2.0/24"}, []string{"10.0.0.0/24"}, []netip.Addr{netip.MustParseAddr("10.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	a.SetRuntime([]string{"eth0"}, true, "5.15", "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := a.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if strings.Count(output.String(), "\n") != 1 || !strings.Contains(output.String(), "203.0.113.2") {
		t.Fatalf("output: %s", output.String())
	}
	if err := a.export(); err != nil {
		t.Fatal(err)
	}
	if strings.Count(output.String(), "\n") != 1 {
		t.Fatalf("unchanged flow was re-emitted: %s", output.String())
	}
}

func TestExportCollapsesTCPSourcePorts(t *testing.T) {
	t.Parallel()
	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("203.0.113.9")
	var output bytes.Buffer
	a, err := New(fakeSnapshotter{records: []flow.Record{
		{SrcIP: src, DstIP: dst, SrcPort: 40000, DstPort: 443, Protocol: 6, Direction: flow.DirectionEgress, Packets: 1, Bytes: 10, Connections: 1},
		{SrcIP: src, DstIP: dst, SrcPort: 40001, DstPort: 443, Protocol: 6, Direction: flow.DirectionEgress, Packets: 4, Bytes: 40},
	}}, &output, time.Hour, 10, nil, nil, []netip.Addr{src})
	if err != nil {
		t.Fatal(err)
	}
	a.SetRuntime([]string{"eth0"}, true, "5.15", "")
	if err := a.export(); err != nil {
		t.Fatal(err)
	}
	if strings.Count(output.String(), "\n") != 1 || strings.Contains(output.String(), "srcPort") || !strings.Contains(output.String(), `"packets":5`) {
		t.Fatalf("output: %s", output.String())
	}
}

func TestChangedCacheHandlesResetDisappearanceAndBound(t *testing.T) {
	t.Parallel()
	source := &fakeSnapshotter{records: []flow.Record{{SrcIP: netip.MustParseAddr("10.0.0.1"), DstIP: netip.MustParseAddr("203.0.113.1"), Protocol: 6, Direction: flow.DirectionEgress, Packets: 2, Connections: 1}}}
	var output bytes.Buffer
	a, err := New(source, &output, time.Hour, 1, nil, nil, []netip.Addr{netip.MustParseAddr("10.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	a.SetRuntime([]string{"eth0"}, true, "5.15", "")
	if err := a.export(); err != nil {
		t.Fatal(err)
	}
	if err := a.export(); err != nil {
		t.Fatal(err)
	}
	source.records[0].Packets = 0 // counter reset must be emitted.
	if err := a.export(); err != nil {
		t.Fatal(err)
	}
	source.records[0].Connections = 2 // connection-only changes must be emitted.
	if err := a.export(); err != nil {
		t.Fatal(err)
	}
	source.records = nil
	if err := a.export(); err != nil {
		t.Fatal(err)
	}
	source.records = []flow.Record{{SrcIP: netip.MustParseAddr("10.0.0.1"), DstIP: netip.MustParseAddr("203.0.113.1"), Protocol: 6, Direction: flow.DirectionEgress, Connections: 1}}
	if err := a.export(); err != nil {
		t.Fatal(err)
	} // reappearance is emitted even with same counters.
	for i := 0; i < 10; i++ {
		source.records = []flow.Record{{SrcIP: netip.MustParseAddr("10.0.0.1"), DstIP: netip.AddrFrom4([4]byte{203, 0, 113, byte(i + 1)}), Protocol: 6, Direction: flow.DirectionEgress, Connections: uint64(i)}}
		if err := a.export(); err != nil {
			t.Fatal(err)
		}
	}
	if len(a.previous) > 3 {
		t.Fatalf("cache size=%d, want <=3", len(a.previous))
	}
	if strings.Count(output.String(), "\n") < 4 {
		t.Fatalf("expected changed emissions: %s", output.String())
	}
}
