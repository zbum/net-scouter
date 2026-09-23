# net-scouter

`net-scouter` is a lightweight Linux network-flow discovery agent for identifying real L3/L4 communication dependencies before server replacement, IP migration, or firewall/ACL changes.

It is designed for production servers: it observes flow metadata only, does not capture packet payloads, and never intentionally drops, modifies, or redirects production traffic.

## Why

Firewall/ACL systems are not always organized around a server-centric view. Before changing a server IP or replacing equipment, operators need to know which systems actually communicate with the target server and which firewall rules may be required after migration.

`net-scouter` observes real traffic over a defined period and produces an ACL-oriented dependency view.

> Observation is evidence, not a guarantee of every possible dependency. Dormant DR paths, monthly jobs, backup paths, or other traffic that does not occur during the observation window cannot be discovered from traffic observation alone.

## Goals

- Observe actual inbound and outbound L3/L4 flows with minimal production overhead.
- Support TCP and UDP over IPv4 and IPv6. ICMP is planned separately because it
  does not have transport ports and therefore is not a 5-tuple flow.
- Aggregate flows in the kernel instead of forwarding every packet to userspace.
- Record first/last seen timestamps, packet count, and byte count.
- Normalize raw flows into an ACL-oriented view.
- Never capture application payloads.
- Fail open: observation failure must not affect production traffic.
- Run on ordinary Linux hosts as well as Kubernetes nodes.

## Supported baseline

Initial target platforms:

- Rocky Linux 8.10 / RHEL 8 compatible kernels.
- Ubuntu 22.04 LTS or newer.

Support is determined primarily by kernel capabilities rather than distro version. The agent should verify at startup that required eBPF/BTF/TC capabilities are available.

The validated Rocky Linux 8.10 environment used during design has a `4.18.0-553.51.1.el8_10.x86_64` kernel with BTF, BPF syscall/JIT, `sched_cls`, LRU hash maps, and the required packet-processing helpers available.

## Architecture

```text
                  Linux host
                      |
             network interface
                      |
          +-----------+-----------+
          |                       |
      TC ingress               TC egress
          |                       |
          +-----------+-----------+
                      |
             eBPF L3/L4 parser
                      |
               BPF LRU hash map
                      |
            periodic map snapshot
                      |
                  Go agent
                      |
          +-----------+-----------+
          |                       |
       JSONL                    stdout
          |
   future collector/API
```

The first implementation uses TC ingress/egress rather than XDP. The goal is observation and dependency discovery, not packet filtering.

## Flow model

Raw flow key:

```text
family + protocol + direction + src IP + dst IP + src port + dst port
```

Aggregated value:

```text
firstSeen
lastSeen
packets
bytes
connections (TCP only)
```

Example raw flow:

```text
10.10.1.20:48321 -> 10.20.1.30:3306 TCP egress
```

ACL-oriented normalization can later collapse ephemeral client ports:

```text
OUTBOUND 10.10.1.20 -> 10.20.1.30 TCP/3306
```

## Safety principles

1. **No payload capture.** Only L3/L4 metadata is observed.
2. **No packet enforcement.** eBPF programs return `TC_ACT_OK` and do not intentionally drop, redirect, or modify packets.
3. **Kernel-side aggregation.** High packet rates should not result in one userspace event per packet.
4. **Bounded state.** Flow state uses an LRU map with a configurable maximum size.
5. **Fail open.** Parsing/map failures must not interfere with traffic.
6. **Capability detection.** Do not assume that a kernel version alone implies support, especially on RHEL-family kernels with backported eBPF features.

## Scope

### v0.1

- [ ] Linux capability check
- [ ] Interface selection
- [x] TC ingress classifier
- [x] TC egress classifier
- [x] IPv4 parsing
- [x] IPv6 parsing
- [x] TCP flows
- [x] UDP flows
- [ ] ICMP/ICMPv6 flows
- [x] Kernel-side LRU flow aggregation
- [x] firstSeen / lastSeen
- [x] packet / byte counters
- [x] TCP established connection counter (Linux 4.18 and 5.15 tracepoint ABI variants)
- [ ] stdout exporter
- [ ] JSONL exporter
- [ ] ACL-oriented normalization
- [ ] destination exclusion rules
- [ ] systemd unit
- [ ] Kubernetes DaemonSet example

### Later

- Central collector
- Existing ACL comparison
- IP migration report
- DNS enrichment
- PID/process attribution
- Container/Kubernetes workload attribution
- Web UI
- Dooray notifications

Process/container attribution is deliberately excluded from v0.1. The first version is a small L3/L4 flow collector.

## Project layout

```text
net-scouter/
├── cmd/net-scouter/       CLI entry point
├── internal/agent/        agent lifecycle
├── internal/ebpf/         eBPF loader/attach layer
├── internal/flow/         flow domain model and ACL normalization
├── internal/exporter/     stdout/JSONL exporters
├── internal/platform/     kernel capability checks
├── bpf/                   eBPF C sources and shared definitions
├── configs/               example configuration
├── deploy/systemd/        systemd unit
├── deploy/kubernetes/     DaemonSet example
├── scripts/               development/runtime checks
└── Makefile
```

## Build approach

The userspace agent is Go. The small kernel-side sensor is eBPF C. `cilium/ebpf` loads the separately installed, ahead-of-time compiled eBPF object.

```text
flow.bpf.c
    |
   clang
    |
eBPF object
    |
flow.bpf.o + net-scouter binary
```

The kernel program can be compiled on a Linux development host with a clang
build that includes the BPF target:

```bash
make build-bpf
```

It exposes separate TC ingress and egress classifiers. Both are observation-only
and always return `TC_ACT_OK`; unsupported or malformed packets are ignored.
IPv4 and IPv6 parsing is bounded by each packet's declared IP length as well as
the skb boundary. IPv6 jumbograms are deliberately ignored in this version.

`make test` performs Linux-target C syntax checks and verifies the source-level
safety and aggregation invariants. A real eBPF ELF build still requires a Linux
development environment (or LLVM installation) whose clang includes the BPF
backend. Loading the resulting object through the kernel verifier must be part
of validation on every supported kernel; the syntax checks cannot substitute
for verifier testing. Linux CI should run `make verify-bpf` and load-test the
object on each supported kernel baseline.

Packet and byte counters use the atomic add operation supported by the 4.18
baseline. `first_seen` is the timestamp from the CPU that wins initial map
insertion. `last_seen` is a best-effort observation timestamp: concurrent CPUs
may store it out of order. This avoids newer BPF CMPXCHG instructions while
preserving exact concurrent packet and byte aggregation.

TCP connection counts come from `sock:inet_sock_set_state` transitions to
`TCP_ESTABLISHED`, not from SYN packet counts. The BPF object contains separate
raw-context variants for the Linux 4.18 layout (`protocol` u8, address offset
31) and Linux 5.15 layout (`protocol` u16, address offset 32). The runtime
loader must inspect tracefs and explicitly attach exactly one matching variant;
it must never attach both. An unknown ABI disables connection counting while
packet and byte collection remains available.

## Build and CI

Release artifacts are built once on an Ubuntu amd64 build node and reused on
all supported systems:

```bash
make test-ci
```

This produces a statically linked `dist/net-scouter-linux-amd64`,
`dist/flow.bpf.o`, and `dist/SHA256SUMS`. `CGO_ENABLED=0` keeps the Go binary
independent of the build server's libc. The BPF object is not distro-specific;
kernel acceptance is tested separately on each supported kernel baseline.

The Jenkins pipeline has three deliberately separate responsibilities:

1. An Ubuntu amd64 build node runs tests and creates the release artifacts.
2. An unprivileged, network-isolated `rockylinux:8.10` container executes the
   already-built Go binary to check Rocky userspace compatibility.
3. Optional dedicated Ubuntu 22.04+ and Rocky 8.10+ nodes ask their own kernel
   verifier to load the BPF object.

Kernel verifier stages are disabled by default. Enable the
`RUN_KERNEL_VERIFIERS` Jenkins parameter only when both configured node labels
resolve to disposable or dedicated verifier nodes. Those nodes need `bpftool`,
a mounted bpffs at `/sys/fs/bpf`, and passwordless sudo for the narrowly scoped
Jenkins command. `make verify-bpf-load` loads all four programs—the two TC
classifiers and the two tracepoint ABI variants—confirms their pins, and removes
the pins immediately. This verifier-only check does not run `tc`, attach a
program to an interface or tracepoint, or modify network configuration. At
runtime, only one matching tracepoint ABI variant may be attached.

For a local Rocky userspace check (Docker is required):

```bash
make build-linux verify-rocky-userspace
```

This container receives no network, drops all capabilities, and mounts only
the artifact directory read-only. A successful container check does not replace
the Rocky kernel verifier gate because containers use the host kernel.

## Configuration

See `configs/net-scouter.yaml`.

The intended configuration model is intentionally small: interfaces, protocol families, aggregation interval/map size, exporter, and exclusions.

Run the current executable slice explicitly:

```bash
sudo net-scouter run --config /etc/net-scouter/net-scouter.yaml
```

It loads `flow.bpf.o`, attaches only to the configured interface allowlist,
selects at most one compatible TCP state tracepoint layout, and emits changed
rows from periodic cumulative map snapshots as JSON Lines to stdout. Each row
contains cumulative counters; unchanged rows are not emitted again. Destination CIDRs are excluded when the
destination matches; workload traffic is excluded only when both endpoints
match a configured workload CIDR. Internal virtual interfaces are rejected
unless `allowVirtualInterfaces: true` is explicitly configured.
Only one process may collect at a time; Linux enforces this with the advisory
lock `/run/net-scouter.lock`. A pre-existing TC filter collision is reported
and collection stops rather than replacing an unknown or stale filter.

This slice does not persist snapshots. Restarting it resets collected state;
the storage-backed `flows` and `status` commands remain a later milestone.
Shutdown removes only filters owned by this process and never removes clsact.

## Commands

Initial CLI contract:

```bash
sudo net-scouter check
sudo net-scouter run --config /etc/net-scouter/net-scouter.yaml
net-scouter status
net-scouter flows
net-scouter report --view acl
```

Only `check` and the basic `run` skeleton are expected in the initial bootstrap. Other commands are roadmap interfaces.

## Important limitations

Traffic observation can only report communication that actually occurs during the observation period. For migration work, observed flows should eventually be compared with existing ACLs and supplemented with information such as listening sockets and relevant operational knowledge.

NAT also matters: the address visible to `net-scouter` depends on the observation hook relative to SNAT/DNAT. ACL reporting must ultimately represent the address seen at the firewall enforcement point.

## Development direction

Keep the eBPF C portion deliberately small. Packet parsing and bounded aggregation belong in eBPF; configuration, reporting, normalization, storage, export, and future integrations belong in Go.
