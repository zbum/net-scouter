package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadDirectionalExclusions(t *testing.T) {
	t.Parallel()
	base := "interfaces: [eth0]\ncapture: {ipv4: true, ipv6: true, tcp: true, udp: true, icmp: false}\nsafety: {failOpen: true}\nexport: {type: stdout}\n"
	tests := []struct {
		name, exclude, wantError string
	}{
		{"all directions", "exclude:\n  destinations: [203.0.113.0/24]\n  workloadCIDRs: [172.20.0.0/16]\n  ingress: {sources: [192.0.2.0/24], destinations: [2001:db8::/32]}\n  egress: {sources: [198.51.100.0/24], destinations: [2001:db8:1::/48]}\n", ""},
		{"invalid ingress source", "exclude:\n  ingress: {sources: [bad]}\n", "exclude.ingress.sources"},
		{"invalid egress destination", "exclude:\n  egress: {destinations: [broken]}\n", "exclude.egress.destinations"},
		{"unknown ingress field", "exclude:\n  ingress: {source: [192.0.2.0/24]}\n", "source"},
		{"unknown egress field", "exclude:\n  egress: {destination: [192.0.2.0/24]}\n", "destination"},
		{"mapped IPv4 range", "exclude:\n  egress: {destinations: ['::ffff:192.0.2.0/120']}\n", ""},
		{"mapped IPv4 range too broad", "exclude:\n  ingress: {sources: ['::ffff:192.0.2.0/95']}\n", "prefix length at least 96"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(base+tt.exclude), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := Load(path)
			if tt.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantError) {
					t.Fatalf("error = %v, want %q", err, tt.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tt.name == "all directions" {
				if len(got.Exclude.Ingress.Sources) != 1 || len(got.Exclude.Ingress.Destinations) != 1 || len(got.Exclude.Egress.Sources) != 1 || len(got.Exclude.Egress.Destinations) != 1 {
					t.Fatalf("directional exclusions = %+v", got.Exclude)
				}
			} else if len(got.Exclude.Egress.Destinations) != 1 || got.Exclude.Egress.Destinations[0] != "::ffff:192.0.2.0/120" {
				t.Fatalf("mapped CIDR = %+v", got.Exclude.Egress)
			}
		})
	}
}

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
	if c.Mode != "exporter" || c.Exporter.Listen != "127.0.0.1:9469" || c.Exporter.MaxFlows != 4096 {
		t.Fatalf("exporter defaults: %+v", c)
	}
	if c.Storage.Path != "/var/lib/net-scouter/flows.db" || c.Storage.FlushInterval.String() != "5m0s" || c.Storage.Retention.String() != "720h0m0s" || c.Storage.MaxEntries != 65536 || c.Storage.MaxBytes != 67108864 {
		t.Fatalf("storage defaults: %+v", c.Storage)
	}
}

func TestLoadModesAndStrictStorage(t *testing.T) {
	t.Parallel()
	base := "interfaces: [eth0]\ncapture: {ipv4: true, ipv6: true, tcp: true, udp: true, icmp: false}\nsafety: {failOpen: true}\n"
	for _, tt := range []struct{ name, suffix, wantError string }{
		{"persistent", "mode: persistent\nstorage: {path: /var/lib/net-scouter/flows.db, flushInterval: 1m, retention: 24h, maxEntries: 100, maxBytes: 1048576}\n", ""},
		{"unknown mode", "mode: both\n", "mode"},
		{"unknown storage field", "storage: {flush: 1m}\n", "flush"},
		{"bad duration", "storage: {flushInterval: never}\n", "storage.flushInterval"},
		{"negative entries", "storage: {maxEntries: -1}\n", "storage"},
		{"relative storage", "storage: {path: flows.db}\n", "storage.path"},
		{"invalid listen", "exporter: {listen: not-an-address}\n", "exporter.listen"},
		{"legacy stdout", "export: {type: stdout}\n", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(base+tt.suffix), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := Load(path)
			if tt.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantError) {
					t.Fatalf("error = %v, want %q", err, tt.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tt.name == "persistent" && (got.Mode != "persistent" || got.Storage.FlushInterval != 1*time.Minute) {
				t.Fatalf("persistent config = %+v", got)
			}
		})
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
