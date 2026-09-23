package flow

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestRecordJSONIncludesTCPConnections(t *testing.T) {
	t.Parallel()

	encoded, err := json.Marshal(Record{Protocol: 6, Connections: 3})
	if err != nil {
		t.Fatalf("marshal Record: %v", err)
	}
	if !strings.Contains(string(encoded), `"connections":3`) {
		t.Fatalf("Record JSON = %s, want TCP connection count", encoded)
	}
}

func TestCollapseTCPSourcePorts(t *testing.T) {
	t.Parallel()
	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("203.0.113.1")
	early := time.Date(2026, 9, 23, 1, 0, 0, 0, time.UTC)
	late := early.Add(time.Minute)
	got := CollapseTCPSourcePorts([]Record{
		{SrcIP: src, DstIP: dst, SrcPort: 40000, DstPort: 443, Protocol: 6, Direction: DirectionEgress, FirstSeen: late, LastSeen: late, Packets: 2, Bytes: 20, Connections: 1},
		{SrcIP: src, DstIP: dst, SrcPort: 40001, DstPort: 443, Protocol: 6, Direction: DirectionEgress, FirstSeen: early, LastSeen: early, Packets: 3, Bytes: 30, Connections: 1},
		{SrcIP: src, DstIP: dst, SrcPort: 1111, DstPort: 53, Protocol: 17, Direction: DirectionEgress, Packets: 1, Bytes: 40},
		{SrcIP: src, DstIP: dst, SrcPort: 2222, DstPort: 53, Protocol: 17, Direction: DirectionEgress, Packets: 1, Bytes: 40},
	})
	if len(got) != 3 {
		t.Fatalf("collapsed len=%d, records=%+v", len(got), got)
	}
	tcp := got[0]
	if tcp.SrcPort != 0 || tcp.DstPort != 443 || tcp.Packets != 5 || tcp.Bytes != 50 || tcp.Connections != 2 || !tcp.FirstSeen.Equal(early) || !tcp.LastSeen.Equal(late) {
		t.Fatalf("tcp collapse = %+v", tcp)
	}
	if got[1].SrcPort != 1111 || got[2].SrcPort != 2222 {
		t.Fatalf("udp source ports changed: %+v", got[1:])
	}
}

func TestRecordJSONOmitsZeroConnections(t *testing.T) {
	t.Parallel()

	encoded, err := json.Marshal(Record{Protocol: 17})
	if err != nil {
		t.Fatalf("marshal Record: %v", err)
	}
	if strings.Contains(string(encoded), `"connections"`) {
		t.Fatalf("Record JSON = %s, want no UDP connection count", encoded)
	}
}
