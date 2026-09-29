package main

import (
	"encoding/json"
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

func TestFlowsDisplayRejectsInvalidFlagsBeforeLoading(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-k", "-m"}, "mutually exclusive"},
		{[]string{"-k", "-h"}, "mutually exclusive"},
		{[]string{"-m", "-h"}, "mutually exclusive"},
		{[]string{"--sort-by=size"}, "sort-by must be"},
	} {
		if err := flowsCmd(tc.args); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("flows %v: %v, want %q", tc.args, err, tc.want)
		}
	}
	if err := flowsCmd([]string{"--help"}); err != nil {
		t.Fatalf("--help: %v", err)
	}
}

func TestFlowsCommandFormatsAndSortsOfflineHistory(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "flows.db")
	store, err := storage.Open(storePath, storage.Options{})
	if err != nil {
		t.Fatal(err)
	}
	when := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	record := flow.Record{
		SrcIP: netip.MustParseAddr("192.0.2.1"), DstIP: netip.MustParseAddr("198.51.100.1"),
		DstPort: 443, Protocol: 6, Direction: flow.DirectionEgress,
		FirstSeen: when, LastSeen: when, Packets: 2, Bytes: 1024, Connections: 1,
	}
	larger := record
	larger.SrcIP = netip.MustParseAddr("192.0.2.2")
	larger.Bytes = 1572864
	larger.Packets = 10
	larger.Connections = 3
	if _, err := store.UpsertBatch([]flow.Record{record, larger}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "net-scouter.yaml")
	if err := os.WriteFile(configPath, []byte("mode: persistent\ninterfaces: [eth0]\ncapture: {ipv4: true, ipv6: true, tcp: true, udp: true, icmp: false}\nsafety: {failOpen: true}\nstorage: {path: "+storePath+"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-k", "--sort-by=PACKET"}, "1536.00 KiB"},
		{[]string{"-m", "--sort-by=BYTE"}, "1.50 MiB"},
		{[]string{"-h", "--sort-by=CONNECTION"}, "1.50 MiB"},
		{[]string{"-h", "--sort-by=bytes", "--format=json"}, ""},
		{[]string{"-k", "--sort-by=p"}, "1536.00 KiB"},
		{[]string{"-m", "--sort-by=b"}, "1.50 MiB"},
		{[]string{"-h", "--sort-by=c"}, "1.50 MiB"},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			output, err := os.CreateTemp(dir, "stdout-*")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { output.Close() })
			stdout := os.Stdout
			os.Stdout = output
			defer func() { os.Stdout = stdout }()
			args := append([]string{"--socket", filepath.Join(dir, "absent.sock"), "--config", configPath, "--local"}, tc.args...)
			if err := flowsCmd(args); err != nil {
				t.Fatal(err)
			}
			body, err := os.ReadFile(output.Name())
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == "" {
				var result query.FlowsResult
				if err := json.Unmarshal(body, &result); err != nil {
					t.Fatal(err)
				}
				if len(result.Records) != 2 || result.Records[0].Bytes != larger.Bytes {
					t.Fatalf("JSON result = %s", body)
				}
			} else {
				text := string(body)
				if !strings.Contains(text, tc.want) || strings.Index(text, "192.0.2.2") >= strings.Index(text, "192.0.2.1") {
					t.Fatalf("unexpected table: %s", text)
				}
			}
		})
	}
}

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
