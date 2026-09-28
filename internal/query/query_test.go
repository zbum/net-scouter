package query

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zbum/net-scouter/internal/flow"
)

func TestPrepareFlowsSeparatesUnavailableConnections(t *testing.T) {
	t.Parallel()
	when := time.Date(2026, 9, 23, 1, 2, 3, 0, time.UTC)
	records := []flow.Record{
		{SrcIP: netip.MustParseAddr("10.0.0.1"), DstIP: netip.MustParseAddr("203.0.113.9"), Protocol: 6, Direction: flow.DirectionEgress, FirstSeen: when, LastSeen: when, Packets: 4, Bytes: 8},
		{SrcIP: netip.MustParseAddr("10.0.0.1"), DstIP: netip.MustParseAddr("203.0.113.8"), Protocol: 17, Direction: flow.DirectionIngress, FirstSeen: when, LastSeen: when.Add(time.Second), Packets: 2, Bytes: 3},
	}
	disabled := PrepareFlows(records, false, "", ConnectionABIUnavailable)
	if disabled.Records[0].DstIP != "203.0.113.8" {
		t.Fatalf("sort = %+v", disabled.Records)
	}
	body, err := FormatFlows(disabled, "json")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, `"connections": null`) {
		t.Fatalf("disabled connections were not null: %s", body)
	}
	table, err := FormatFlows(disabled, "table")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(table, "n/a") || !strings.Contains(table, "unavailable") {
		t.Fatalf("table did not explain unavailable connections: %s", table)
	}

	enabled := PrepareFlows([]flow.Record{records[0]}, true, "4.18", "")
	if enabled.Records[0].Connections == nil || *enabled.Records[0].Connections != 0 {
		t.Fatalf("zero TCP connections = %#v", enabled.Records[0].Connections)
	}
	udp := PrepareFlows([]flow.Record{records[1]}, true, "5.15", "")
	if udp.Records[0].Connections != nil {
		t.Fatal("UDP connection count was populated")
	}
	lines, err := FormatFlows(enabled, "jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(lines, `"type":"meta"`) || !strings.Contains(lines, `"connections":0`) {
		t.Fatalf("jsonl = %s", lines)
	}
}

func TestFilterProtocol(t *testing.T) {
	t.Parallel()
	when := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	result := PrepareFlows([]flow.Record{
		{SrcIP: netip.MustParseAddr("10.0.0.1"), DstIP: netip.MustParseAddr("10.0.0.2"), Protocol: 6, DstPort: 22, Direction: flow.DirectionIngress, FirstSeen: when, LastSeen: when},
		{SrcIP: netip.MustParseAddr("10.0.0.1"), DstIP: netip.MustParseAddr("203.0.113.53"), Protocol: 17, DstPort: 53, Direction: flow.DirectionEgress, FirstSeen: when, LastSeen: when},
	}, true, "5.15", "")
	both, err := FilterProtocol(result, "both")
	if err != nil || len(both.Records) != 2 {
		t.Fatalf("both: %v %+v", err, both.Records)
	}
	tcp, err := FilterProtocol(result, "tcp")
	if err != nil || len(tcp.Records) != 1 || tcp.Records[0].Protocol != 6 {
		t.Fatalf("tcp: %v %+v", err, tcp.Records)
	}
	udp, err := FilterProtocol(result, "udp")
	if err != nil || len(udp.Records) != 1 || udp.Records[0].DstPort != 53 {
		t.Fatalf("udp: %v %+v", err, udp.Records)
	}
	if _, err := FilterProtocol(result, "icmp"); err == nil {
		t.Fatal("icmp was accepted")
	}
}

func TestFilterEstablishedHidesFailedTCPByDefault(t *testing.T) {
	t.Parallel()
	when := time.Date(2026, 9, 24, 0, 42, 26, 0, time.UTC)
	zero := uint64(0)
	one := uint64(1)
	result := FlowsResult{
		ConnectionsAvailable: true,
		Records: []FlowView{
			{SrcIP: "198.51.100.20", DstIP: "203.0.113.53", Protocol: 6, DstPort: 53, Direction: flow.DirectionEgress, FirstSeen: when, LastSeen: when, Packets: 10, Connections: &one},
			{SrcIP: "198.51.100.20", DstIP: "192.0.2.100", Protocol: 6, DstPort: 23827, Direction: flow.DirectionEgress, FirstSeen: when, LastSeen: when, Packets: 3, Connections: &zero},
			{SrcIP: "198.51.100.20", DstIP: "203.0.113.53", Protocol: 17, DstPort: 53, Direction: flow.DirectionEgress, FirstSeen: when, LastSeen: when, Packets: 1},
		},
	}
	established := FilterEstablished(result, false)
	if len(established.Records) != 2 || established.Records[0].DstPort != 53 || established.Records[1].Protocol != 17 {
		t.Fatalf("established = %+v", established.Records)
	}
	all := FilterEstablished(result, true)
	if len(all.Records) != 3 {
		t.Fatalf("attempts = %+v", all.Records)
	}
	unavailable := result
	unavailable.ConnectionsAvailable = false
	if got := FilterEstablished(unavailable, false); len(got.Records) != 1 || got.Records[0].Protocol != 17 {
		t.Fatalf("unverified TCP flows leaked while connection counts are unavailable: %+v", got.Records)
	}
}

func TestLoadStatusUsesSavedFileWhenAgentIsGone(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "status.json")
	saved := Status{
		PID:            0,
		StartedAt:      time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC),
		Interfaces:     []string{"eth0"},
		DurableStorage: DurableUnavailable,
		DurableReason:  DurableReason,
		LastError:      "snapshot flows: device busy",
		Exclude:        ExcludeStatus{Destinations: []string{}, WorkloadCIDRs: []string{"10.0.0.0/24"}},
	}
	if err := WriteStatus(path, saved); err != nil {
		t.Fatal(err)
	}
	got, err := LoadStatus(filepath.Join(dir, "missing.sock"), path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Running || !got.Stale || got.Source != "status-file" || got.LastError == "" {
		t.Fatalf("status = %+v", got)
	}
	text := FormatStatus(got)
	if !strings.Contains(text, "stale") || !strings.Contains(text, "device busy") || !strings.Contains(text, "10.0.0.0/24") {
		t.Fatalf("rendered status: %s", text)
	}
}

func TestLoadStatusReportsNoAgent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	got, err := LoadStatus(filepath.Join(dir, "missing.sock"), filepath.Join(dir, "missing.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Running || got.Source != "none" {
		t.Fatalf("status = %+v", got)
	}
	if !strings.Contains(FormatStatus(got), "not running") {
		t.Fatal(FormatStatus(got))
	}
}

func TestFormatStatusShowsCapacity(t *testing.T) {
	t.Parallel()
	text := FormatStatus(Status{
		Live: true, Running: true, Source: "agent", PID: 9,
		StartedAt:      time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC),
		Interfaces:     []string{"eth0"},
		Map:            MapStatus{Entries: 2, MaxEntries: 2, AtCapacity: true, PossibleLoss: true},
		Connections:    ConnectionStatus{Enabled: true, ABI: "5.15"},
		Exclude:        ExcludeStatus{Destinations: []string{}, WorkloadCIDRs: []string{}},
		DurableStorage: DurableUnavailable, DurableReason: DurableReason,
	})
	if !strings.Contains(text, "running") || !strings.Contains(text, "at capacity") || !strings.Contains(text, "trace ABI 5.15") {
		t.Fatalf("status text: %s", text)
	}
}

func TestFormatStatusShowsDirectionalExclusions(t *testing.T) {
	t.Parallel()
	st := Status{
		Source: "agent",
		Exclude: ExcludeStatus{
			Ingress: DirectionExclusions{Sources: []string{"192.0.2.0/24"}, Destinations: []string{"10.0.0.0/24"}},
			Egress:  DirectionExclusions{Sources: []string{"2001:db8::/32"}, Destinations: []string{"198.51.100.0/24"}},
		},
	}
	text := FormatStatus(st)
	for _, want := range []string{"ingress sources:       192.0.2.0/24", "ingress destinations:  10.0.0.0/24", "egress sources:        2001:db8::/32", "egress destinations:   198.51.100.0/24"} {
		if !strings.Contains(text, want) {
			t.Fatalf("status text missing %q: %s", want, text)
		}
	}
	body, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"ingress":{"sources":["192.0.2.0/24"]`, `"egress":{"sources":["2001:db8::/32"]`} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("status JSON missing %q: %s", want, body)
		}
	}
}

func TestFormatStatusShowsModeSpecificRuntime(t *testing.T) {
	t.Parallel()
	persistent := FormatStatus(Status{
		Source: "agent", Mode: "persistent", DurableStorage: DurableDegraded, DurableReason: "disk full",
		Storage: StorageStatus{
			Path: "/var/lib/net-scouter/flows.db", Schema: 1, Entries: 8, FileBytes: 4096,
			MaxEntries: 100, MaxBytes: 10240, Retention: "720h0m0s", ExpiredTotal: 2, EvictedTotal: 3, Error: "disk full",
		},
	})
	for _, want := range []string{"mode:                  persistent", "storage path:          /var/lib/net-scouter/flows.db", "storage entries:       8 / 100", "storage error:         disk full"} {
		if !strings.Contains(persistent, want) {
			t.Fatalf("persistent status missing %q: %s", want, persistent)
		}
	}
	exporter := FormatStatus(Status{
		Source: "agent", Mode: "exporter", DurableStorage: DurableDisabled,
		Exporter: ExporterStatus{Listen: "127.0.0.1:9469", Published: 4, Omitted: 2},
	})
	for _, want := range []string{"mode:                  exporter", "metrics listen:        127.0.0.1:9469", "published / omitted:   4 / 2"} {
		if !strings.Contains(exporter, want) {
			t.Fatalf("exporter status missing %q: %s", want, exporter)
		}
	}
}

func TestFormatStatusShowsDurableStorageReasonForItsState(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		state  string
		reason string
		want   string
	}{
		{name: "ready", state: DurableReady, want: "durable storage:       ready\n"},
		{name: "disabled fallback", state: DurableDisabled, want: "durable storage:       disabled (persistent mode is not enabled)\n"},
		{name: "degraded fallback", state: DurableDegraded, want: "durable storage:       degraded (storage error not specified)\n"},
		{name: "degraded detail", state: DurableDegraded, reason: "disk full", want: "durable storage:       degraded (disk full)\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for _, source := range []string{"agent", "none"} {
				st := Status{Source: source, DurableStorage: tc.state, DurableReason: tc.reason}
				got := FormatStatus(st)
				if !strings.Contains(got, tc.want) {
					t.Fatalf("source %q: expected %q in status:\n%s", source, tc.want, got)
				}
				if tc.state == DurableReady && strings.Contains(got, DurableReason) {
					t.Fatalf("source %q: ready status has disabled reason:\n%s", source, got)
				}
				body, err := json.Marshal(st)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(body), `"durableStorageReason":"`+tc.reason+`"`) {
					t.Fatalf("source %q: JSON reason changed: %s", source, body)
				}
			}
		})
	}
}

func TestFormatStatusShowsSeparateMemoryEvictions(t *testing.T) {
	t.Parallel()
	st := Status{Source: "agent", Mode: "persistent", MemoryEvictedTotal: 7, Storage: StorageStatus{EvictedTotal: 3}}
	got := FormatStatus(st)
	if !strings.Contains(got, "memory evicted:        7\n") || !strings.Contains(got, "expired / evicted:     0 / 3\n") {
		t.Fatalf("memory and durable evictions were conflated:\n%s", got)
	}
	body, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"memoryEvictedTotal":7`) || !strings.Contains(string(body), `"evictedTotal":3`) {
		t.Fatalf("memory and durable eviction JSON: %s", body)
	}
}

func TestFormatFlowsShowsDurableStorageStateWithoutReason(t *testing.T) {
	t.Parallel()
	for _, state := range []string{DurableReady, DurableDisabled, DurableDegraded} {
		result := FlowsResult{DurableStorage: state}
		got, err := FormatFlows(result, "table")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(got, "durable storage: "+state+"\n") || strings.Contains(got, DurableReason) {
			t.Fatalf("state %q: unexpected table:\n%s", state, got)
		}
	}
}

func TestWriteStatusRoundTrip(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "status.json")
	want := absentStatus()
	want.PID = os.Getpid()
	if err := WriteStatus(path, want); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(body) {
		t.Fatalf("invalid status json: %s", body)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
}
