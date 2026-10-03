package agent

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/zbum/net-scouter/internal/flow"
	"github.com/zbum/net-scouter/internal/storage"
)

func TestDockerNetworksOnlySelectsDockerBridgeSubnets(t *testing.T) {
	interfaces := []net.Interface{{Name: "docker0"}, {Name: "br-012345abcdef"}, {Name: "eth0"}, {Name: "br-office"}, {Name: "veth123"}}
	prefixes, err := dockerNetworks(interfaces, func(i net.Interface) ([]net.Addr, error) {
		if i.Name == "eth0" || i.Name == "br-office" || i.Name == "veth123" {
			t.Fatalf("unexpected lookup: %s", i.Name)
		}
		values := []string{"172.18.0.1/16", "fd00:1234::1/64", "fe80::1/64"}
		var addresses []net.Addr
		for _, value := range values {
			_, p, err := net.ParseCIDR(value)
			if err != nil {
				t.Fatal(err)
			}
			addresses = append(addresses, p)
		}
		return addresses, nil
	})
	if err != nil || len(prefixes) != 2 {
		t.Fatalf("networks=%v err=%v", prefixes, err)
	}
	a := &Agent{dockerNetworks: prefixes}
	for _, tc := range []struct {
		src, dst string
		excluded bool
	}{
		{"172.18.0.4", "192.168.31.102", true},
		{"192.168.31.102", "172.18.0.4", true},
		{"fd00:1234::4", "2001:db8::1", true},
		{"::ffff:172.18.0.4", "192.168.31.102", true},
		{"192.168.31.185", "192.168.31.102", false},
		{"172.19.0.4", "192.168.31.102", false},
		{"192.168.31.102", "8.8.4.4", false},
	} {
		r := flow.Record{SrcIP: netip.MustParseAddr(tc.src), DstIP: netip.MustParseAddr(tc.dst), Direction: flow.DirectionIngress}
		if got := a.excluded(r); got != tc.excluded {
			t.Errorf("%s -> %s excluded=%v", tc.src, tc.dst, got)
		}
	}
}

func TestDockerDiscoveryFailureIsReported(t *testing.T) {
	_, err := dockerNetworks([]net.Interface{{Name: "docker0"}}, func(net.Interface) ([]net.Addr, error) { return nil, errors.New("lookup failed") })
	if err == nil {
		t.Fatal("expected discovery error")
	}
}

func TestDockerExclusionsApplyBeforeAggregationAndToHistory(t *testing.T) {
	a := configuredAgent(t, &fakeSnapshotter{})
	a.dockerLookup = func() ([]netip.Prefix, error) {
		return []netip.Prefix{netip.MustParsePrefix("172.18.0.0/16")}, nil
	}
	allowed := testRecord(1, 10, 1000, 1)
	docker := allowed
	docker.DstIP = netip.MustParseAddr("172.18.0.4")
	inbound := docker
	inbound.SrcIP, inbound.DstIP = docker.DstIP, docker.SrcIP
	inbound.Direction = flow.DirectionIngress
	inbound.Packets, inbound.Bytes = 0, 0
	rows := []flow.Record{allowed, docker, inbound}
	if err := a.ingestLocked(rows); err != nil {
		t.Fatal(err)
	}
	if len(a.stored) != 1 || len(a.baselines) != 1 {
		t.Fatalf("Docker flows entered aggregation: stored=%d baselines=%d", len(a.stored), len(a.baselines))
	}
	for _, filtered := range [][]flow.Record{a.visible(rows), a.FilterHistorical(rows), a.currentFlowsLocked()} {
		if len(filtered) != 1 || filtered[0].DstIP != allowed.DstIP {
			t.Fatalf("unexpected visible records: %+v", filtered)
		}
	}
}

func TestDockerRefreshEvictsStoredFlowsAndRetainsRulesOnError(t *testing.T) {
	record := flow.Record{SrcIP: netip.MustParseAddr("172.18.0.4"), DstIP: netip.MustParseAddr("192.168.31.102"), Protocol: 6, Direction: flow.DirectionIngress, DstPort: 443}
	key, err := storage.EncodeKey(record)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	a := &Agent{
		stored:         map[storage.Key]flow.Record{key: record},
		dirtyKeys:      map[storage.Key]struct{}{key: {}},
		persistedKeys:  map[storage.Key]struct{}{key: {}},
		pendingDeletes: make(map[storage.Key]struct{}),
		dockerLookup: func() ([]netip.Prefix, error) {
			calls++
			return []netip.Prefix{netip.MustParsePrefix("172.18.0.0/16")}, nil
		},
	}
	a.refreshDockerNetworks()
	if len(a.stored) != 0 || len(a.dirtyKeys) != 0 || len(a.pendingDeletes) != 1 {
		t.Fatal("Docker history was not scheduled for removal")
	}
	a.refreshDockerNetworks()
	if calls != 1 {
		t.Fatal("discovery was not cached")
	}
	a.dockerChecked = time.Time{}
	a.dockerLookup = func() ([]netip.Prefix, error) { return nil, errors.New("temporary failure") }
	a.refreshDockerNetworks()
	if !a.excluded(record) || a.dockerError == "" {
		t.Fatal("lost exclusions or error")
	}
	if len(a.statusLocked().DockerNetworks) != 1 {
		t.Fatal("missing status exclusions")
	}
	a.dockerChecked = time.Time{}
	a.dockerLookup = func() ([]netip.Prefix, error) { return nil, nil }
	a.refreshDockerNetworks()
	if a.excluded(record) || a.dockerError != "" {
		t.Fatal("removed network not refreshed")
	}
}
