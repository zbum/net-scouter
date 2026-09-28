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

func TestForACLDropsReturnPathAndCollapsesPorts(t *testing.T) {
	t.Parallel()
	server := netip.MustParseAddr("198.51.100.20")
	client := netip.MustParseAddr("192.0.2.10")
	resolver := netip.MustParseAddr("203.0.113.53")
	got := ForACL([]Record{
		{SrcIP: client, DstIP: server, SrcPort: 50000, DstPort: 22, Protocol: 6, Direction: DirectionIngress, Packets: 10, Bytes: 100},
		{SrcIP: server, DstIP: client, SrcPort: 22, DstPort: 50000, Protocol: 6, Direction: DirectionEgress, Packets: 8, Bytes: 80},
		{SrcIP: server, DstIP: resolver, SrcPort: 40000, DstPort: 53, Protocol: 17, Direction: DirectionEgress, Packets: 1, Bytes: 40},
		{SrcIP: server, DstIP: resolver, SrcPort: 40001, DstPort: 53, Protocol: 17, Direction: DirectionEgress, Packets: 1, Bytes: 40},
		{SrcIP: resolver, DstIP: server, SrcPort: 53, DstPort: 40000, Protocol: 17, Direction: DirectionIngress, Packets: 1, Bytes: 80},
	})
	if len(got) != 2 {
		t.Fatalf("len=%d records=%+v", len(got), got)
	}
	if got[0].DstPort != 22 || got[0].SrcPort != 0 || got[0].Direction != DirectionIngress || got[0].Packets != 10 {
		t.Fatalf("inbound = %+v", got[0])
	}
	if got[1].DstPort != 53 || got[1].SrcPort != 0 || got[1].Direction != DirectionEgress || got[1].Packets != 2 || got[1].Bytes != 80 {
		t.Fatalf("outbound = %+v", got[1])
	}
}

func TestForACLRawPreservesKernelSourcePortsForDeltaAccounting(t *testing.T) {
	t.Parallel()
	host := netip.MustParseAddr("10.0.0.1")
	remote := netip.MustParseAddr("192.0.2.5")
	got := ForACLRaw([]Record{
		{SrcIP: host, DstIP: remote, SrcPort: 40000, DstPort: 443, Protocol: 6, Direction: DirectionEgress, Connections: 1},
		{SrcIP: host, DstIP: remote, SrcPort: 40001, DstPort: 443, Protocol: 6, Direction: DirectionEgress, Connections: 1},
		{SrcIP: remote, DstIP: host, SrcPort: 443, DstPort: 40000, Protocol: 6, Direction: DirectionIngress},
	})
	if len(got) != 2 || got[0].SrcPort != 40000 || got[1].SrcPort != 40001 {
		t.Fatalf("raw ACL records = %+v", got)
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
