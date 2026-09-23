package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/example/net-scouter/internal/agent"
	"github.com/example/net-scouter/internal/config"
	loader "github.com/example/net-scouter/internal/ebpf"
	"github.com/example/net-scouter/internal/platform"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "check":
		if err := platform.PrintCheck(os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "check failed:", err)
			os.Exit(1)
		}
	case "run":
		if err := run(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "run failed:", err)
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: net-scouter <check|run --config PATH>")
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
	if !connections {
		fmt.Fprintln(os.Stderr, "warning: TCP connection counting disabled: unknown or unavailable tracepoint ABI")
	}
	a, err := agent.New(l, os.Stdout, cfg.Aggregation.Interval, cfg.Aggregation.MaxFlows, cfg.Exclude.Destinations, cfg.Exclude.WorkloadCIDRs)
	if err != nil {
		return err
	}
	return a.Run(ctx)
}
