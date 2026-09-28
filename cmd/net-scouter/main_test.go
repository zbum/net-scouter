package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zbum/net-scouter/internal/flow"
	"github.com/zbum/net-scouter/internal/query"
	"github.com/zbum/net-scouter/internal/storage"
	"net/netip"
)

func TestOfflineFlowsReadsDurableHistoryAndAppliesCurrentCIDRs(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	storePath := filepath.Join(dir, "flows.db")
	store, err := storage.Open(storePath, storage.Options{})
	if err != nil {
		t.Fatal(err)
	}
	when := time.Now().UTC()
	base := flow.Record{
		SrcIP: netip.MustParseAddr("10.0.0.1"), DstIP: netip.MustParseAddr("192.0.2.5"),
		DstPort: 443, Protocol: 6, Direction: flow.DirectionEgress,
		FirstSeen: when, LastSeen: when, Packets: 5, Connections: 1,
	}
	blocked := base
	blocked.DstIP = netip.MustParseAddr("198.51.100.5")
	if _, err := store.UpsertBatch([]flow.Record{base, blocked}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "net-scouter.yaml")
	body := "mode: persistent\ninterfaces: [eth0]\ncapture: {ipv4: true, ipv6: true, tcp: true, udp: true, icmp: false}\nsafety: {failOpen: true}\nstorage: {path: " + storePath + "}\nexclude:\n  egress: {destinations: [198.51.100.0/24]}\n"
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := offlineFlows(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if result.DurableStorage != query.DurableReady || len(result.Records) != 1 || result.Records[0].DstIP != "192.0.2.5" {
		t.Fatalf("offline flows = %+v", result)
	}
}

func TestOfflineFlowsExplainsExporterModeHasNoHistory(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "net-scouter.yaml")
	body := "interfaces: [eth0]\ncapture: {ipv4: true, ipv6: true, tcp: true, udp: true, icmp: false}\nsafety: {failOpen: true}\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := offlineFlows(path)
	if err == nil || !strings.Contains(err.Error(), "no flow history") {
		t.Fatalf("error = %v", err)
	}
}
