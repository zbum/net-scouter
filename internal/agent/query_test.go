package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/zbum/net-scouter/internal/flow"
	"github.com/zbum/net-scouter/internal/query"
)

func TestQueryFiltersFlowsAndReportsCapacity(t *testing.T) {
	t.Parallel()
	when := time.Date(2026, 9, 23, 4, 5, 6, 0, time.UTC)
	source := &fakeSnapshotter{records: []flow.Record{
		{SrcIP: netip.MustParseAddr("10.1.0.1"), DstIP: netip.MustParseAddr("192.0.2.10"), Protocol: 6, Direction: flow.DirectionIngress, FirstSeen: when, LastSeen: when, Packets: 1, Bytes: 1},
		{SrcIP: netip.MustParseAddr("10.1.0.1"), DstIP: netip.MustParseAddr("10.1.0.2"), Protocol: 6, Direction: flow.DirectionEgress, FirstSeen: when, LastSeen: when, Packets: 1, Bytes: 1},
		{SrcIP: netip.MustParseAddr("10.1.0.1"), DstIP: netip.MustParseAddr("203.0.113.10"), Protocol: 6, Direction: flow.DirectionEgress, FirstSeen: when, LastSeen: when.Add(time.Minute), Packets: 8, Bytes: 90, Connections: 2},
	}}
	var output bytes.Buffer
	a, err := New(source, &output, time.Minute, 2, []string{"192.0.2.0/24"}, []string{"10.1.0.0/24"}, []netip.Addr{netip.MustParseAddr("10.1.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	a.SetRuntime([]string{"eth0"}, false, "4.18", "")
	dir := t.TempDir()
	statusPath := filepath.Join(dir, "status.json")
	if err := a.EnableStatusFile(statusPath); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	socketPath := shortSocket(t)
	if err := a.StartQuery(ctx, socketPath); err != nil {
		t.Fatal(err)
	}

	flows, err := query.LoadFlows(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(flows.Records) != 1 || flows.Records[0].DstIP != "203.0.113.10" {
		t.Fatalf("flows = %+v", flows.Records)
	}
	if flows.ConnectionsAvailable || flows.Records[0].Connections != nil {
		t.Fatalf("disabled connection state leaked: %+v", flows)
	}
	status, err := query.LoadStatus(socketPath, statusPath)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Live || !status.Running || !status.Map.PossibleLoss || status.Map.Entries != 3 || status.Map.MaxEntries != 2 {
		t.Fatalf("status = %+v", status)
	}
	if status.Connections.Enabled || status.Connections.Detail == "" {
		t.Fatalf("connection status = %+v", status.Connections)
	}
	saved, err := query.ReadStatus(statusPath)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Map.Entries != 3 || len(saved.Interfaces) != 1 || saved.Interfaces[0] != "eth0" {
		t.Fatalf("saved status = %+v", saved)
	}
	text, err := query.FormatFlows(flows, "json")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, `"connections": null`) {
		t.Fatalf("flow json = %s", text)
	}
}

func TestDirectionalExclusionsApplyToQueryExportAndStatus(t *testing.T) {
	t.Parallel()
	host := netip.MustParseAddr("10.0.0.1")
	source := fakeSnapshotter{records: []flow.Record{
		{SrcIP: host, DstIP: netip.MustParseAddr("192.0.2.5"), Protocol: 6, Direction: flow.DirectionEgress, DstPort: 443, Connections: 1},
		{SrcIP: host, DstIP: netip.MustParseAddr("198.51.100.5"), Protocol: 6, Direction: flow.DirectionEgress, DstPort: 443, Connections: 1},
	}}
	var output bytes.Buffer
	a, err := New(source, &output, time.Hour, 10, nil, nil, []netip.Addr{host})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.SetDirectionalExclusions(DirectionExclusions{}, DirectionExclusions{Destinations: []string{"192.0.2.0/24"}}); err != nil {
		t.Fatal(err)
	}
	a.SetRuntime([]string{"eth0"}, true, "5.15", "")
	statusPath := filepath.Join(t.TempDir(), "status.json")
	if err := a.EnableStatusFile(statusPath); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	socketPath := shortSocket(t)
	if err := a.StartQuery(ctx, socketPath); err != nil {
		t.Fatal(err)
	}
	flows, err := query.LoadFlows(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(flows.Records) != 1 || flows.Records[0].DstIP != "198.51.100.5" {
		t.Fatalf("query flows = %+v", flows.Records)
	}
	if err := a.export(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "192.0.2.5") || !strings.Contains(output.String(), "198.51.100.5") {
		t.Fatalf("export = %s", output.String())
	}
	status, err := query.ReadStatus(statusPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Exclude.Egress.Destinations) != 1 || status.Exclude.Egress.Destinations[0] != "192.0.2.0/24" {
		t.Fatalf("status exclusions = %+v", status.Exclude)
	}
}

func shortSocket(t *testing.T) string {
	t.Helper()
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		t.Fatal(err)
	}
	dir := "/tmp"
	if runtime.GOOS == "windows" {
		dir = t.TempDir()
	}
	path := filepath.Join(dir, fmt.Sprintf("ns-%x.sock", buf))
	t.Cleanup(func() { os.Remove(path) })
	return path
}
