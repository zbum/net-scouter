package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/zbum/net-scouter/internal/agent"
	"github.com/zbum/net-scouter/internal/config"
	loader "github.com/zbum/net-scouter/internal/ebpf"
	"github.com/zbum/net-scouter/internal/metrics"
	"github.com/zbum/net-scouter/internal/platform"
	"github.com/zbum/net-scouter/internal/query"
	"github.com/zbum/net-scouter/internal/storage"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "check":
		err = platform.PrintCheck(os.Stdout)
	case "run":
		err = run(os.Args[2:])
	case "status":
		err = statusCmd(os.Args[2:])
	case "flows":
		err = flowsCmd(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, os.Args[1]+" failed:", err)
		os.Exit(1)
	}
}

func configuredNICAddrs(path string) []netip.Addr {
	cfg, err := config.Load(path)
	if err != nil {
		return nil
	}
	return query.InterfaceAddrs(cfg.Interfaces)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: net-scouter <check|run --config PATH|status [--format text|json]|flows [--protocol tcp|udp|both] [--attempts] [--local] [-k|-m|-h] [--sort-by packets|bytes|connections] [--config PATH] [--format table|json|jsonl] [--help]>")
}

func run(args []string) (runErr error) {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if len(args) != 2 || args[0] != "--config" {
		return fmt.Errorf("run requires --config PATH")
	}
	cfg, err := config.Load(args[1])
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	hostAddrs, err := agent.ResolveHostAddresses(cfg.Interfaces, *cfg.Capture.IPv4, *cfg.Capture.IPv6)
	if err != nil {
		return err
	}
	instanceLock, err := agent.AcquireInstanceLock("/run/net-scouter.lock")
	if err != nil {
		return err
	}
	defer func() { runErr = errors.Join(runErr, instanceLock.Close()) }()
	l, err := loader.Open(cfg.ObjectPath, cfg.Aggregation.MaxFlows)
	if err != nil {
		return err
	}
	defer func() { runErr = errors.Join(runErr, l.Close()) }()
	if err := l.SetHostAddresses(hostAddrs); err != nil {
		return err
	}
	if err := l.SetCapture(*cfg.Capture.IPv4, *cfg.Capture.IPv6, *cfg.Capture.TCP, *cfg.Capture.UDP); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := l.AttachTC(cfg.Interfaces, cfg.AllowVirtual); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	connections, err := l.AttachTracepoint()
	if err != nil {
		return err
	}
	enabled, abi := l.ConnectionCounting()
	if connections != enabled {
		return fmt.Errorf("connection counting state mismatch")
	}
	detail := ""
	if !enabled {
		detail = query.ConnectionABIUnavailable
		fmt.Fprintln(os.Stderr, "warning: TCP connection counting disabled:", detail)
	}
	a, err := agent.New(l, os.Stdout, cfg.Aggregation.Interval, cfg.Aggregation.MaxFlows, cfg.Exclude.Destinations, cfg.Exclude.WorkloadCIDRs, hostAddrs)
	if err != nil {
		return err
	}
	if err := a.SetDirectionalExclusions(
		agent.DirectionExclusions{Sources: cfg.Exclude.Ingress.Sources, Destinations: cfg.Exclude.Ingress.Destinations},
		agent.DirectionExclusions{Sources: cfg.Exclude.Egress.Sources, Destinations: cfg.Exclude.Egress.Destinations},
	); err != nil {
		return err
	}
	a.SetRuntime(cfg.Interfaces, enabled, abi, detail)
	a.SetCapture(*cfg.Capture.IPv4, *cfg.Capture.IPv6, *cfg.Capture.TCP, *cfg.Capture.UDP)
	if cfg.Export.Type == "stdout" {
		a.EnableLegacyStdout()
	}
	switch cfg.Mode {
	case "exporter":
		if err := a.ConfigureExporter(metrics.New(cfg.Exporter.Listen, cfg.Exporter.MaxFlows), cfg.Exporter.MaxFlows); err != nil {
			return err
		}
	case "persistent":
		if err := os.MkdirAll(filepath.Dir(cfg.Storage.Path), 0o700); err != nil {
			return fmt.Errorf("create storage directory: %w", err)
		}
		store, err := storage.Open(cfg.Storage.Path, storage.Options{MaxBytes: cfg.Storage.MaxBytes})
		if err != nil {
			return err
		}
		defer func() { runErr = errors.Join(runErr, store.Close()) }()
		if err := a.ConfigurePersistent(store, cfg.Storage.Path, cfg.Storage.FlushInterval, storage.Retention{
			InactiveTTL: cfg.Storage.Retention, MaxEntries: cfg.Storage.MaxEntries, MaxBytes: cfg.Storage.MaxBytes,
		}); err != nil {
			return err
		}
	}
	if err := a.EnableStatusFile(query.DefaultStatusPath); err != nil {
		return err
	}
	if err := a.StartQuery(ctx, query.DefaultSocketPath); err != nil {
		return err
	}
	return a.Run(ctx)
}

func statusCmd(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	format := fs.String("format", "text", "text or json")
	socketPath := fs.String("socket", query.DefaultSocketPath, "agent query socket")
	statusFile := fs.String("status-file", query.DefaultStatusPath, "saved status file")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments")
	}
	st, err := query.LoadStatus(*socketPath, *statusFile)
	switch *format {
	case "text":
		fmt.Fprint(os.Stdout, query.FormatStatus(st))
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(st); encErr != nil {
			return encErr
		}
	default:
		return fmt.Errorf("unknown status format %q", *format)
	}
	return err
}

func flowsCmd(args []string) error {
	fs := flag.NewFlagSet("flows", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	format := fs.String("format", "table", "table, json, or jsonl")
	protocol := fs.String("protocol", "tcp", "tcp, udp, or both")
	kilobytes := fs.Bool("k", false, "display table bytes in KiB (1024 bytes)")
	megabytes := fs.Bool("m", false, "display table bytes in MiB (1048576 bytes)")
	human := fs.Bool("h", false, "display table bytes with automatic units; use --help for help")
	sortBy := fs.String("sort-by", "", "sort descending by packets (p), bytes (b), or connections (c)")
	attempts := fs.Bool("attempts", false, "include TCP connection attempts that did not establish")
	includeLocal := fs.Bool("local", false, "include loopback and flows that stay on the configured NIC addresses")
	configPath := fs.String("config", "/etc/net-scouter/net-scouter.yaml", "config used to resolve NIC addresses")
	socketPath := fs.String("socket", query.DefaultSocketPath, "agent query socket")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments")
	}
	options := query.FlowDisplayOptions{SortBy: *sortBy}
	for _, unit := range []struct {
		enabled bool
		name    string
	}{{*kilobytes, "k"}, {*megabytes, "m"}, {*human, "h"}} {
		if unit.enabled {
			if options.ByteUnit != "" {
				return fmt.Errorf("-k, -m, and -h are mutually exclusive")
			}
			options.ByteUnit = unit.name
		}
	}
	if err := options.Validate(); err != nil {
		return err
	}
	load := query.LoadFlows
	if *attempts {
		load = query.LoadFlowAttempts
	}
	result, err := load(*socketPath)
	if err != nil {
		if !errors.Is(err, query.ErrAgentUnavailable) {
			return err
		}
		result, err = offlineFlows(*configPath)
		if err != nil {
			return err
		}
	}
	result, err = query.FilterProtocol(result, *protocol)
	if err != nil {
		return err
	}
	if *attempts && *protocol != "udp" {
		fmt.Fprintln(os.Stderr, "warning: --attempts includes packet-only NIC flows; NATed container traffic may use the host address")
	}
	result = query.FilterEstablished(result, *attempts)
	result = query.FilterLocal(result, *includeLocal, configuredNICAddrs(*configPath))
	text, err := query.FormatFlowsWithOptions(result, *format, options)
	if err != nil {
		return err
	}
	_, err = io.WriteString(os.Stdout, text)
	return err
}

func offlineFlows(configPath string) (query.FlowsResult, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return query.FlowsResult{}, fmt.Errorf("offline flows require a readable config: %w", err)
	}
	if cfg.Mode != "persistent" {
		return query.FlowsResult{}, fmt.Errorf("exporter mode has no flow history after the agent stops")
	}
	store, err := storage.OpenReadOnly(cfg.Storage.Path)
	if err != nil {
		return query.FlowsResult{}, err
	}
	defer store.Close()
	records, err := store.Load()
	if err != nil {
		return query.FlowsResult{}, err
	}
	records, err = agent.FilterHistoricalRecords(records, cfg.Exclude.Destinations, cfg.Exclude.WorkloadCIDRs,
		agent.DirectionExclusions{Sources: cfg.Exclude.Ingress.Sources, Destinations: cfg.Exclude.Ingress.Destinations},
		agent.DirectionExclusions{Sources: cfg.Exclude.Egress.Sources, Destinations: cfg.Exclude.Egress.Destinations})
	if err != nil {
		return query.FlowsResult{}, err
	}
	result := query.PrepareFlows(records, true, "historical", "")
	result.HistoricalConnections = true
	result.ConnectionABI = ""
	result.DurableStorage = query.DurableReady
	return result, nil
}
