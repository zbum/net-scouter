#!/usr/bin/env bash
set -euo pipefail

object=${1:-dist/flow.bpf.o}
pin_root=${BPF_PIN_ROOT:-/sys/fs/bpf}
pin_dir=
owns_pin_dir=0

if [[ $(uname -s) != Linux ]]; then
  echo "kernel verifier loading requires Linux" >&2
  exit 1
fi
if [[ ! -f "$object" ]]; then
  echo "BPF object not found: $object" >&2
  exit 1
fi
if ! command -v bpftool >/dev/null 2>&1; then
  echo "bpftool is required on verifier nodes" >&2
  exit 1
fi
if [[ ! -d "$pin_root" ]] || ! mountpoint -q "$pin_root"; then
  echo "bpffs must be mounted at $pin_root" >&2
  exit 1
fi

cleanup() {
  if [[ "$owns_pin_dir" -eq 1 && -n "$pin_dir" && -d "$pin_dir" ]]; then
    find "$pin_dir" -mindepth 1 -maxdepth 1 -type f -delete
    rmdir "$pin_dir"
  fi
}
trap cleanup EXIT INT TERM

# bpffs rejects names containing dots.
pin_dir=$(mktemp -d "${pin_root}/net-scouter-verify-XXXXXXXX")
owns_pin_dir=1
bpftool prog loadall "$object" "$pin_dir"

loaded=$(find "$pin_dir" -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d ' ')
if [[ "$loaded" -ne 4 ]]; then
  echo "expected two classifiers and two tracepoint ABI variants, found $loaded" >&2
  exit 1
fi

echo "kernel verifier load: OK (programs were not attached)"
