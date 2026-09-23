#!/usr/bin/env bash
# Print the package version. A release branch sets VERSION. Without that
# file, development builds use 0.0.0+UTC.git so they still sort after 0+git.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

if [[ -f VERSION ]]; then
	version=$(tr -d '[:space:]' < VERSION)
	if [[ ! "$version" =~ ^[0-9]+(\.[0-9A-Za-z]+)*$ ]]; then
		echo "invalid VERSION: $version" >&2
		exit 1
	fi
	printf '%s\n' "$version"
	exit 0
fi

hash=unknown
dirty=""
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
	hash=$(git rev-parse --short=12 HEAD)
	if [[ -n "$(git status --porcelain)" ]]; then
		dirty=".dirty"
	fi
fi
printf '0.0.0+%s.%s%s\n' "$(date -u +%Y%m%d%H%M%S)" "$hash" "$dirty"
