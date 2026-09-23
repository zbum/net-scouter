package ebpf

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/example/net-scouter/internal/flow"
)

func DecodeRecord(k FlowKey, v FlowValue, wallNow time.Time, monotonicNow time.Duration) (flow.Record, error) {
	if k.Protocol != 6 && k.Protocol != 17 {
		return flow.Record{}, fmt.Errorf("unsupported protocol %d", k.Protocol)
	}
	if k.Direction != uint8(flow.DirectionIngress) && k.Direction != uint8(flow.DirectionEgress) {
		return flow.Record{}, fmt.Errorf("invalid direction %d", k.Direction)
	}
	var src, dst netip.Addr
	switch k.Family {
	case 2:
		src = netip.AddrFrom4([4]byte(k.SrcAddr[:4]))
		dst = netip.AddrFrom4([4]byte(k.DstAddr[:4]))
	case 10:
		src = netip.AddrFrom16(k.SrcAddr)
		dst = netip.AddrFrom16(k.DstAddr)
	default:
		return flow.Record{}, fmt.Errorf("unsupported address family %d", k.Family)
	}
	boot := wallNow.Add(-monotonicNow)
	return flow.Record{SrcIP: src, DstIP: dst, SrcPort: k.SrcPort, DstPort: k.DstPort, Protocol: k.Protocol, Direction: flow.Direction(k.Direction), FirstSeen: boot.Add(time.Duration(v.FirstSeenNS)), LastSeen: boot.Add(time.Duration(v.LastSeenNS)), Packets: v.Packets, Bytes: v.Bytes, Connections: v.Connections}, nil
}
