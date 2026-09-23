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

func TestRunFiltersDestinationAndSameHostWorkload(t *testing.T) {
	t.Parallel()
	records := []flow.Record{
		{SrcIP: netip.MustParseAddr("10.0.0.1"), DstIP: netip.MustParseAddr("192.0.2.1"), Protocol: 6, Direction: 1},
		{SrcIP: netip.MustParseAddr("10.0.0.1"), DstIP: netip.MustParseAddr("10.0.0.2"), Protocol: 6, Direction: 1},
		{SrcIP: netip.MustParseAddr("10.0.0.1"), DstIP: netip.MustParseAddr("203.0.113.2"), Protocol: 6, Direction: 1},
	}
	var output bytes.Buffer
	a, err := New(fakeSnapshotter{records}, &output, time.Hour, 10, []string{"192.0.2.0/24"}, []string{"10.0.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
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

func TestChangedCacheHandlesResetDisappearanceAndBound(t *testing.T) {
	t.Parallel()
	source := &fakeSnapshotter{records: []flow.Record{{SrcIP: netip.MustParseAddr("10.0.0.1"), DstIP: netip.MustParseAddr("203.0.113.1"), Protocol: 6, Direction: 1, Packets: 2}}}
	var output bytes.Buffer
	a, err := New(source, &output, time.Hour, 1, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
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
	source.records[0].Connections = 1 // connection-only changes must be emitted.
	if err := a.export(); err != nil {
		t.Fatal(err)
	}
	source.records = nil
	if err := a.export(); err != nil {
		t.Fatal(err)
	}
	source.records = []flow.Record{{SrcIP: netip.MustParseAddr("10.0.0.1"), DstIP: netip.MustParseAddr("203.0.113.1"), Protocol: 6, Direction: 1}}
	if err := a.export(); err != nil {
		t.Fatal(err)
	} // reappearance is emitted even with same counters.
	for i := 0; i < 10; i++ {
		source.records = []flow.Record{{SrcIP: netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)}), DstIP: netip.MustParseAddr("203.0.113.1"), Protocol: 6, Direction: 1, Connections: uint64(i)}}
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
