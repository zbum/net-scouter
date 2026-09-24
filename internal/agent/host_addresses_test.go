package agent

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/example/net-scouter/internal/flow"
	"github.com/example/net-scouter/internal/query"
)

func TestResolveHostAddressesSelectsEnabledFamiliesAndEveryInterface(t *testing.T) {
	t.Parallel()
	lookup := func(name string) ([]net.Addr, error) {
		switch name {
		case "eth0":
			return []net.Addr{&net.IPNet{IP: net.ParseIP("192.0.2.10")}, &net.IPNet{IP: net.ParseIP("2001:db8::10")}}, nil
		case "eth1":
			return []net.Addr{&net.IPNet{IP: net.ParseIP("192.0.2.11")}, &net.IPNet{IP: net.ParseIP("192.0.2.10")}}, nil
		default:
			return nil, errors.New("missing interface")
		}
	}
	got, err := resolveHostAddresses([]string{"eth0", "eth1"}, true, false, lookup)
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.11")}
	if !slices.Equal(got, want) {
		t.Fatalf("addresses = %v, want %v", got, want)
	}
	if _, err := resolveHostAddresses([]string{"eth0", "missing"}, true, true, lookup); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing interface error = %v", err)
	}
	if _, err := resolveHostAddresses([]string{"eth1"}, false, true, lookup); err == nil || !strings.Contains(err.Error(), "no address") {
		t.Fatalf("missing enabled family error = %v", err)
	}
}

func TestHostAddressScopeKeepsOnlySelectedLocalEndpoints(t *testing.T) {
	t.Parallel()
	host4 := netip.MustParseAddr("192.0.2.10")
	host6 := netip.MustParseAddr("2001:db8::10")
	container1 := netip.MustParseAddr("172.20.0.5")
	container2 := netip.MustParseAddr("172.20.0.2")
	remote4 := netip.MustParseAddr("198.51.100.20")
	remote6 := netip.MustParseAddr("2001:db8::20")
	records := []flow.Record{
		{SrcIP: host4, DstIP: remote4, Protocol: 6, Direction: flow.DirectionEgress, DstPort: 443, Connections: 1},
		{SrcIP: remote4, DstIP: host4, Protocol: 6, Direction: flow.DirectionIngress, DstPort: 22, Connections: 1},
		{SrcIP: host6, DstIP: remote6, Protocol: 6, Direction: flow.DirectionEgress, DstPort: 443, Connections: 1},
		{SrcIP: container1, DstIP: container2, Protocol: 6, Direction: flow.DirectionEgress, DstPort: 3003, Connections: 1},
		{SrcIP: container1, DstIP: remote4, Protocol: 6, Direction: flow.DirectionEgress, DstPort: 443, Connections: 1},
		{SrcIP: remote4, DstIP: container2, Protocol: 6, Direction: flow.DirectionIngress, DstPort: 3003, Connections: 1},
		{SrcIP: container1, DstIP: remote4, Protocol: 17, Direction: flow.DirectionEgress, DstPort: 53},
	}
	a, err := New(fakeSnapshotter{records}, nil, time.Minute, 100, nil, nil, []netip.Addr{host4, host6})
	if err != nil {
		t.Fatal(err)
	}
	a.SetRuntime([]string{"eth0", "eth1"}, true, "5.15", "")
	result, err := a.Flows()
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Records) != 3 {
		t.Fatalf("visible flows = %+v", result.Records)
	}
	for _, record := range result.Records {
		if strings.Contains(record.SrcIP, "172.20") || strings.Contains(record.DstIP, "172.20") {
			t.Fatalf("workload socket escaped host address scope: %+v", record)
		}
	}
	status := a.Status()
	if !slices.Equal(status.HostAddresses, []string{"192.0.2.10", "2001:db8::10"}) {
		t.Fatalf("status host addresses = %v", status.HostAddresses)
	}
}

func TestHostAddressScopeRejectsEmptySetAndHidesUnverifiedTCP(t *testing.T) {
	t.Parallel()
	if _, err := New(fakeSnapshotter{}, nil, time.Minute, 10, nil, nil, nil); err == nil {
		t.Fatal("empty selected address set enabled unrestricted collection")
	}
	host := netip.MustParseAddr("192.0.2.10")
	a, err := New(fakeSnapshotter{[]flow.Record{
		{SrcIP: host, DstIP: netip.MustParseAddr("198.51.100.20"), Protocol: 6, Direction: flow.DirectionEgress, DstPort: 443, Packets: 10},
	}}, nil, time.Minute, 10, nil, nil, []netip.Addr{host})
	if err != nil {
		t.Fatal(err)
	}
	a.SetRuntime([]string{"eth0"}, false, "", "tracepoint unavailable")
	result, err := a.Flows()
	if err != nil {
		t.Fatal(err)
	}
	if got := query.FilterEstablished(result, false); len(got.Records) != 0 {
		t.Fatalf("unverified packet-only TCP in default result: %+v", got.Records)
	}
	if got := query.FilterEstablished(result, true); len(got.Records) != 1 {
		t.Fatalf("explicit attempts result = %+v", got.Records)
	}
}
