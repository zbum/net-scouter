#!/usr/bin/env bash
set -euo pipefail

source_file="bpf/flow.bpf.c"
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
if [[ $(grep -c 'drop_ephemeral_source_port(' "$source_file") -ne 3 ]]; then
  echo "ephemeral source port must be omitted from packet and connection keys" >&2
  exit 1
fi
grep -q 'parse_ports(cursor + header_length, packet_end, data_end' "$source_file"
grep -q 'parse_ports(cursor, packet_end, data_end' "$source_file"
grep -q '(void \*)(ports + 1) > packet_end' "$source_file"
grep -q '(void \*)(ports + 1) > data_end' "$source_file"
grep -q '(void \*)(fragment + 1) > packet_end' "$source_file"
grep -q '(void \*)(fragment + 1) > data_end' "$source_file"
grep -q '(void \*)(ext + 1) > packet_end' "$source_file"
grep -q '(void \*)(ext + 1) > data_end' "$source_file"
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

clang -target x86_64-unknown-linux-gnu -std=gnu11 -fsyntax-only \
  -Wall -Wextra -Werror -Ibpf "$source_file"
echo "eBPF safety invariants: OK"
