package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/example/net-scouter/internal/agent"
	"github.com/example/net-scouter/internal/config"
	loader "github.com/example/net-scouter/internal/ebpf"
	"github.com/example/net-scouter/internal/platform"
	"github.com/example/net-scouter/internal/query"
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

func usage() {
	fmt.Fprintln(os.Stderr, "usage: net-scouter <check|run --config PATH|status [--format text|json]|flows [--format table|json|jsonl]>")
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
	a, err := agent.New(l, os.Stdout, cfg.Aggregation.Interval, cfg.Aggregation.MaxFlows, cfg.Exclude.Destinations, cfg.Exclude.WorkloadCIDRs)
	if err != nil {
		return err
	}
	a.SetRuntime(cfg.Interfaces, enabled, abi, detail)
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
	result, err := query.LoadFlows(*socketPath)
	if err != nil {
		return err
	}
	text, err := query.FormatFlows(result, *format)
	if err != nil {
		return err
	}
	_, err = io.WriteString(os.Stdout, text)
	return err
}
