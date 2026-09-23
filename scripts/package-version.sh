#!/usr/bin/env bash
# Print a package version that apt and dnf treat as newer than an older
# publish. 0.0.0+UTC.git sorts after the earlier 0+git versions.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

hash=unknown
dirty=""
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
	hash=$(git rev-parse --short=12 HEAD)
	if [[ -n "$(git status --porcelain)" ]]; then
		dirty=".dirty"
	fi
fi
printf '0.0.0+%s.%s%s\n' "$(date -u +%Y%m%d%H%M%S)" "$hash" "$dirty"
