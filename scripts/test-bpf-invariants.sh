#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  root=$(cd "$(dirname "$0")/.." && pwd)
  image="${DEB_BUILD_IMAGE:-net-scouter-deb-build:22.04}"
  platform="${DEB_BUILD_PLATFORM:-linux/amd64}"
  "$root/scripts/ensure-build-image.sh" "$image" "$root/deploy/docker/deb-build.Dockerfile" "$platform"
  exec docker run --rm --platform "$platform" --network none \
    -u "$(id -u):$(id -g)" -v "$root:/work:ro" -w /work \
    "$image" bash scripts/test-bpf-invariants.sh
fi

source_file="bpf/flow.bpf.c"
BPF_CLANG="${BPF_CLANG:-clang}"
classifiers=$(grep -c '^SEC("classifier/' "$source_file")
act_ok_returns=$(grep -c 'return TC_ACT_OK;' "$source_file")

if [[ "$classifiers" -ne 2 ]]; then
  echo "expected exactly two TC classifiers, found $classifiers" >&2
  exit 1
fi
if [[ "$act_ok_returns" -lt 3 ]]; then
  echo "TC programs must fail open on every observation path" >&2
  exit 1
fi
if grep -Eq 'bpf_(skb_store_bytes|clone_redirect|redirect)|TC_ACT_(SHOT|REDIRECT|STOLEN)' "$source_file"; then
  echo "packet mutation, redirect, or drop helper/action found" >&2
  exit 1
fi
if grep -Eq 'bpf_perf_event_output|bpf_ringbuf_|BPF_MAP_TYPE_(PERF_EVENT_ARRAY|RINGBUF)' "$source_file"; then
  echo "per-packet export or payload handling found" >&2
  exit 1
fi

grep -q 'BPF_MAP_TYPE_LRU_HASH' "$source_file"
grep -q 'IPPROTO_TCP' "$source_file"
grep -q 'IPPROTO_UDP' "$source_file"
grep -q 'FLOW_FAMILY_IPV4' "$source_file"
grep -q 'FLOW_FAMILY_IPV6' "$source_file"
if [[ $(grep -c '^SEC("tracepoint/sock/inet_sock_set_state_u' "$source_file") -ne 2 ]]; then
  echo "expected u8 and u16 inet_sock_set_state ABI variants" >&2
  exit 1
fi
grep -q 'int tcp_conn_u8(' "$source_file"
grep -q 'int tcp_conn_u16(' "$source_file"
grep -q 'protocol size 1/saddr offset 31 selects tcp_conn_u8' "$source_file"
grep -q 'size 2/offset 32' "$source_file"
grep -q 'event->newstate != TCP_ESTABLISHED' "$source_file"
grep -q 'event->oldstate == TCP_SYN_SENT' "$source_file"
grep -q 'event->oldstate == TCP_SYN_RECV' "$source_file"
grep -q 'event->oldstate == TCP_NEW_SYN_RECV' "$source_file"
grep -q '__sync_fetch_and_add(&current->connections, 1)' "$source_file"
grep -q 'total_length < header_length + sizeof(struct ports_hdr)' "$source_file"
grep -q 'payload_length == 0' "$source_file"
grep -q 'drop_ephemeral_source_port' "$source_file"
grep -q 'reply_to_client' "$source_file"
grep -q 'capture_cfg' "$source_file"
grep -q 'capture_allowed' "$source_file"
grep -q 'host_address_allowed' "$source_file"
grep -q 'host_addrs' "$source_file"
grep -q 'source_mapped != destination_mapped' "$source_file"
grep -q 'set_connection_addresses(&key, event)' "$source_file"
if [[ $(grep -c 'host_address_allowed(&key)' "$source_file") -ne 2 ]]; then
  echo "TC and TCP tracepoint must both use the host address scope" >&2
  exit 1
fi
if [[ $(grep -c 'drop_ephemeral_source_port(' "$source_file") -ne 3 ]]; then
  echo "ephemeral source port must be omitted from packet and connection keys" >&2
  exit 1
fi
grep -q 'bpf_skb_load_bytes' "$source_file"
grep -q 'parse_ports(skb, network_offset + header_length' "$source_file"
grep -q 'parse_ports(skb, offset, remaining' "$source_file"
grep -q 'remaining < sizeof(ports)' "$source_file"
grep -q 'remaining < sizeof(fragment)' "$source_file"
grep -q 'remaining < sizeof(ext)' "$source_file"
if grep -Eq 'cursor \+ (total_length|payload_length|length)|cursor \+= length' "$source_file"; then
  echo "packet pointers must not use packet-derived variable lengths" >&2
  exit 1
fi
if grep -Eq '__sync_(bool|val)_compare_and_swap|cmpxchg|-mcpu=v3' "$source_file" Makefile; then
  echo "4.18 baseline must not depend on BPF CMPXCHG or ISA v3" >&2
  exit 1
fi
grep -q '^BPF_CPU ?= v1$' Makefile
grep -q -- '-mcpu=$(BPF_CPU)' Makefile
if [[ $(grep -c 'bpf_map_lookup_elem(&flows, key)' "$source_file") -lt 2 ]]; then
  echo "BPF_NOEXIST race loser must retry the map lookup" >&2
  exit 1
fi

"$BPF_CLANG" -std=gnu11 -fsyntax-only \
  -Wall -Wextra -Werror -Ibpf "$source_file"
address_test=$(mktemp)
trap 'rm -f "$address_test"' EXIT
"$BPF_CLANG" -std=gnu11 -O2 -Wall -Wextra -Werror -Ibpf \
  scripts/test-bpf-addresses.c -o "$address_test"
"$address_test"
echo "eBPF safety invariants: OK"
