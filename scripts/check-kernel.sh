#!/usr/bin/env bash
set -euo pipefail

uname -r
if [[ -r /sys/kernel/btf/vmlinux ]]; then
  echo "BTF: yes"
else
  echo "BTF: no"
fi

if command -v bpftool >/dev/null 2>&1; then
  sudo bpftool feature probe kernel
else
  echo "bpftool: not installed"
fi
