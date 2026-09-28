#!/bin/sh
set -eu

minimum_major=1
minimum_minor=26

if [ "$#" -gt 1 ]; then
	echo "usage: $0 [go-version]" >&2
	exit 2
fi

version=${1:-}
if [ -z "$version" ]; then
	go_bin=${GO_BIN:-go}
	if ! command -v "$go_bin" >/dev/null 2>&1; then
		echo "Go 1.26 or newer is required; '$go_bin' was not found" >&2
		exit 1
	fi

	version=$($go_bin env GOVERSION 2>/dev/null || true)
	if [ -z "$version" ]; then
		version=$($go_bin version 2>/dev/null | sed -n 's/^go version \(go[^ ]*\).*$/\1/p')
	fi
fi

parsed=$(printf '%s\n' "$version" | sed -nE \
	's/^go([0-9]+)\.([0-9]+)(\.[0-9]+([a-z]+[0-9]*)?|[a-z]+[0-9]*)?$/\1 \2/p')
if [ -z "$parsed" ]; then
	echo "cannot parse Go version '$version'; Go 1.26 or newer is required" >&2
	exit 1
fi

major=${parsed%% *}
minor=${parsed#* }
if [ "$major" -lt "$minimum_major" ] || \
	{ [ "$major" -eq "$minimum_major" ] && [ "$minor" -lt "$minimum_minor" ]; }; then
	echo "Go $minimum_major.$minimum_minor or newer is required; found $version" >&2
	exit 1
fi

echo "Go version check: $version"
