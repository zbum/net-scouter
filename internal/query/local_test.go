package query

import (
	"net/netip"
	"testing"

	"github.com/zbum/net-scouter/internal/flow"
)

func TestFilterLocalDropsLoopbackAndHostNIC(t *testing.T) {
	t.Parallel()
	host := netip.MustParseAddr("198.51.100.20")
	result := FlowsResult{Records: []FlowView{
		{SrcIP: "127.0.0.1", DstIP: "127.0.0.1", Protocol: 6, DstPort: 6379, Direction: flow.DirectionEgress},
		{SrcIP: "::1", DstIP: "::1", Protocol: 6, DstPort: 2283, Direction: flow.DirectionEgress},
		{SrcIP: "::ffff:127.0.0.1", DstIP: "127.0.0.1", Protocol: 6, DstPort: 8081, Direction: flow.DirectionIngress},
		{SrcIP: "198.51.100.20", DstIP: "198.51.100.20", Protocol: 6, DstPort: 22, Direction: flow.DirectionIngress},
		{SrcIP: "192.0.2.10", DstIP: "198.51.100.20", Protocol: 6, DstPort: 22, Direction: flow.DirectionIngress},
		{SrcIP: "198.51.100.20", DstIP: "203.0.113.53", Protocol: 17, DstPort: 53, Direction: flow.DirectionEgress},
		{SrcIP: "172.17.0.6", DstIP: "172.17.0.6", Protocol: 6, DstPort: 4369, Direction: flow.DirectionEgress},
		{SrcIP: "::ffff:172.17.0.6", DstIP: "172.17.0.6", Protocol: 6, DstPort: 4369, Direction: flow.DirectionIngress},
		{SrcIP: "172.17.0.1", DstIP: "172.17.0.5", Protocol: 6, DstPort: 8081, Direction: flow.DirectionEgress},
	}}
	got := FilterLocal(result, false, []netip.Addr{host})
	if len(got.Records) != 3 {
		t.Fatalf("kept %+v", got.Records)
	}
	if got.Records[0].SrcIP != "192.0.2.10" || got.Records[1].DstIP != "203.0.113.53" || got.Records[2].SrcIP != "172.17.0.1" {
		t.Fatalf("records = %+v", got.Records)
	}
	if all := FilterLocal(result, true, []netip.Addr{host}); len(all.Records) != len(result.Records) {
		t.Fatalf("include local = %+v", all.Records)
	}
}
