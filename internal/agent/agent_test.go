package agent

import (
	"bytes"
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/zbum/net-scouter/internal/flow"
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

func TestDirectionalExclusionsMatchOnlyConfiguredEndpointAndDirection(t *testing.T) {
	t.Parallel()
	host4 := netip.MustParseAddr("10.0.0.1")
	remote4 := netip.MustParseAddr("192.0.2.5")
	host6 := netip.MustParseAddr("2001:db8::1")
	remote6 := netip.MustParseAddr("2001:db8:1::5")
	tests := []struct {
		name             string
		ingress, egress  DirectionExclusions
		blocked, allowed flow.Record
	}{
		{
			name: "ingress source IPv4", ingress: DirectionExclusions{Sources: []string{"192.0.2.0/24"}},
			blocked: flow.Record{SrcIP: remote4, DstIP: host4, Direction: flow.DirectionIngress},
			allowed: flow.Record{SrcIP: host4, DstIP: remote4, Direction: flow.DirectionEgress},
		},
		{
			name: "ingress destination IPv4", ingress: DirectionExclusions{Destinations: []string{"10.0.0.0/24"}},
			blocked: flow.Record{SrcIP: remote4, DstIP: host4, Direction: flow.DirectionIngress},
			allowed: flow.Record{SrcIP: host4, DstIP: remote4, Direction: flow.DirectionEgress},
		},
		{
			name: "egress source IPv4", egress: DirectionExclusions{Sources: []string{"10.0.0.0/24"}},
			blocked: flow.Record{SrcIP: host4, DstIP: remote4, Direction: flow.DirectionEgress},
			allowed: flow.Record{SrcIP: remote4, DstIP: host4, Direction: flow.DirectionIngress},
		},
		{
			name: "egress destination IPv6", egress: DirectionExclusions{Destinations: []string{"2001:db8:1::/48"}},
			blocked: flow.Record{SrcIP: host6, DstIP: remote6, Direction: flow.DirectionEgress},
			allowed: flow.Record{SrcIP: remote6, DstIP: host6, Direction: flow.DirectionIngress},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := New(fakeSnapshotter{}, &bytes.Buffer{}, time.Hour, 10, nil, nil, []netip.Addr{host4, host6})
			if err != nil {
				t.Fatal(err)
			}
			if err := a.SetDirectionalExclusions(tt.ingress, tt.egress); err != nil {
				t.Fatal(err)
			}
			if got := a.visible([]flow.Record{tt.blocked, tt.allowed}); len(got) != 1 || got[0].Direction != tt.allowed.Direction {
				t.Fatalf("visible = %+v, want %+v", got, tt.allowed)
			}
		})
	}
}

func TestDirectionalExclusionsRejectInvalidCIDRWithoutChangingRules(t *testing.T) {
	t.Parallel()
	host := netip.MustParseAddr("10.0.0.1")
	remote := netip.MustParseAddr("192.0.2.5")
	a, err := New(fakeSnapshotter{}, &bytes.Buffer{}, time.Hour, 10, nil, nil, []netip.Addr{host})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.SetDirectionalExclusions(DirectionExclusions{Sources: []string{"192.0.2.0/24"}}, DirectionExclusions{}); err != nil {
		t.Fatal(err)
	}
	if err := a.SetDirectionalExclusions(DirectionExclusions{}, DirectionExclusions{Destinations: []string{"bad"}}); err == nil {
		t.Fatal("invalid CIDR accepted")
	}
	if got := a.visible([]flow.Record{{SrcIP: remote, DstIP: host, Direction: flow.DirectionIngress}}); len(got) != 0 {
		t.Fatalf("previous rule was changed: %+v", got)
	}
}

func TestDirectionalExclusionsRejectUnknownDirection(t *testing.T) {
	t.Parallel()
	host := netip.MustParseAddr("10.0.0.1")
	a, err := New(fakeSnapshotter{}, &bytes.Buffer{}, time.Hour, 10, nil, nil, []netip.Addr{host})
	if err != nil {
		t.Fatal(err)
	}
	if got := a.visible([]flow.Record{{SrcIP: host, DstIP: netip.MustParseAddr("192.0.2.5"), Direction: flow.Direction(99)}}); len(got) != 0 {
		t.Fatalf("unknown direction was visible: %+v", got)
	}
}

func TestDirectionalExclusionsUseORAndLeaveUnmatchedEndpoints(t *testing.T) {
	t.Parallel()
	hostA := netip.MustParseAddr("10.0.0.1")
	hostB := netip.MustParseAddr("10.1.0.1")
	remoteA := netip.MustParseAddr("192.0.2.5")
	remoteB := netip.MustParseAddr("198.51.100.5")
	a, err := New(fakeSnapshotter{}, &bytes.Buffer{}, time.Hour, 10, nil, nil, []netip.Addr{hostA, hostB})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.SetDirectionalExclusions(
		DirectionExclusions{Sources: []string{"192.0.2.0/24"}, Destinations: []string{"10.0.0.1/32"}},
		DirectionExclusions{Sources: []string{"10.0.0.1/32"}, Destinations: []string{"192.0.2.0/24"}},
	); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name        string
		record      flow.Record
		wantVisible bool
	}{
		{"ingress source match", flow.Record{SrcIP: remoteA, DstIP: hostB, Direction: flow.DirectionIngress}, false},
		{"ingress destination match", flow.Record{SrcIP: remoteB, DstIP: hostA, Direction: flow.DirectionIngress}, false},
		{"ingress both mismatch", flow.Record{SrcIP: remoteB, DstIP: hostB, Direction: flow.DirectionIngress}, true},
		{"egress source match", flow.Record{SrcIP: hostA, DstIP: remoteB, Direction: flow.DirectionEgress}, false},
		{"egress destination match", flow.Record{SrcIP: hostB, DstIP: remoteA, Direction: flow.DirectionEgress}, false},
		{"egress both mismatch", flow.Record{SrcIP: hostB, DstIP: remoteB, Direction: flow.DirectionEgress}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := a.visible([]flow.Record{tt.record})
			if (len(got) == 1) != tt.wantVisible {
				t.Fatalf("visible = %+v, wantVisible = %t", got, tt.wantVisible)
			}
		})
	}
}

func TestMappedIPv4CIDRsMatchMappedRecordsInAllExclusionModes(t *testing.T) {
	t.Parallel()
	host := netip.MustParseAddr("10.0.0.1")
	mappedRecord := flow.Record{
		SrcIP:     netip.MustParseAddr("::ffff:10.0.0.1"),
		DstIP:     netip.MustParseAddr("::ffff:192.0.2.5"),
		Direction: flow.DirectionEgress,
	}
	for _, tt := range []struct {
		name             string
		global, workload []string
		egress           DirectionExclusions
	}{
		{"global", []string{"::ffff:192.0.2.0/120"}, nil, DirectionExclusions{}},
		{"workload", nil, []string{"::ffff:10.0.0.0/120", "::ffff:192.0.2.0/120"}, DirectionExclusions{}},
		{"directional", nil, nil, DirectionExclusions{Destinations: []string{"::ffff:192.0.2.0/120"}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a, err := New(fakeSnapshotter{}, &bytes.Buffer{}, time.Hour, 10, tt.global, tt.workload, []netip.Addr{host})
			if err != nil {
				t.Fatal(err)
			}
			if err := a.SetDirectionalExclusions(DirectionExclusions{}, tt.egress); err != nil {
				t.Fatal(err)
			}
			if got := a.visible([]flow.Record{mappedRecord}); len(got) != 0 {
				t.Fatalf("mapped record visible = %+v", got)
			}
		})
	}
}

func TestMappedIPv4CIDRRejectsPrefixShorterThan96(t *testing.T) {
	t.Parallel()
	host := netip.MustParseAddr("10.0.0.1")
	if _, err := New(fakeSnapshotter{}, &bytes.Buffer{}, time.Hour, 10, []string{"::ffff:192.0.2.0/95"}, nil, []netip.Addr{host}); err == nil {
		t.Fatal("legacy mapped CIDR with prefix shorter than 96 accepted")
	}
	a, err := New(fakeSnapshotter{}, &bytes.Buffer{}, time.Hour, 10, nil, nil, []netip.Addr{host})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.SetDirectionalExclusions(DirectionExclusions{Sources: []string{"::ffff:192.0.2.0/95"}}, DirectionExclusions{}); err == nil {
		t.Fatal("directional mapped CIDR with prefix shorter than 96 accepted")
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
