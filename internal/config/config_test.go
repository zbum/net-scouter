package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRejectsUnknownAndVirtual(t *testing.T) {
	t.Parallel()
	for _, body := range []string{"interfaces: [eth0]\nunknown: true\n", "interfaces: [veth0]\n", "interfaces: [eth0]\naggregation:\n  interval: 1s\n  typo: true\n"} {
		p := filepath.Join(t.TempDir(), "c.yaml")
		if err := os.WriteFile(p, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil {
			t.Fatalf("Load(%q) succeeded", body)
		}
	}
}

func TestLoadAppliesDefaults(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "c.yaml")
	body := "interfaces: [eth0]\ncapture: {ipv4: true, ipv6: true, tcp: true, udp: true, icmp: false}\nsafety: {failOpen: true}\nexport: {type: stdout}\n"
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Aggregation.MaxFlows != 65536 || c.Aggregation.Interval.String() != "30s" {
		t.Fatalf("defaults: %+v", c)
	}
	if c.ObjectPath != "/usr/lib/net-scouter/flow.bpf.o" {
		t.Fatalf("object path=%q", c.ObjectPath)
	}
}

func TestLoadAllowsDisablingOneFamily(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "c.yaml")
	body := "interfaces: [eth0]\ncapture: {ipv4: true, ipv6: false, tcp: true, udp: true, icmp: false}\nsafety: {failOpen: true}\nexport: {type: stdout}\n"
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Capture.IPv6 == nil || *c.Capture.IPv6 {
		t.Fatalf("ipv6 = %v", c.Capture.IPv6)
	}
}

func TestLoadRejectsTrailingDocumentAndExcessiveMap(t *testing.T) {
	t.Parallel()
	base := "interfaces: [eth0]\ncapture: {ipv4: true, ipv6: true, tcp: true, udp: true, icmp: false}\nsafety: {failOpen: true}\nexport: {type: stdout}\n"
	for _, suffix := range []string{"---\ninterfaces: [eth1]\n", "aggregation: {interval: 1s, maxFlows: 1048577}\n"} {
		p := filepath.Join(t.TempDir(), "c.yaml")
		body := base + suffix
		if err := os.WriteFile(p, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil {
			t.Fatalf("accepted %q", suffix)
		}
	}
}
