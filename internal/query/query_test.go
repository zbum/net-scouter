package query

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/example/net-scouter/internal/flow"
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
		{SrcIP: netip.MustParseAddr("10.0.0.1"), DstIP: netip.MustParseAddr("8.8.8.8"), Protocol: 17, DstPort: 53, Direction: flow.DirectionEgress, FirstSeen: when, LastSeen: when},
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
			{SrcIP: "192.168.31.102", DstIP: "8.8.8.8", Protocol: 6, DstPort: 53, Direction: flow.DirectionEgress, FirstSeen: when, LastSeen: when, Packets: 10, Connections: &one},
			{SrcIP: "192.168.31.102", DstIP: "69.5.169.100", Protocol: 6, DstPort: 23827, Direction: flow.DirectionEgress, FirstSeen: when, LastSeen: when, Packets: 3, Connections: &zero},
			{SrcIP: "192.168.31.102", DstIP: "8.8.8.8", Protocol: 17, DstPort: 53, Direction: flow.DirectionEgress, FirstSeen: when, LastSeen: when, Packets: 1},
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
