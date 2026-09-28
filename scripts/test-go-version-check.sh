#!/bin/sh
set -eu

checker=${CHECKER:-./scripts/check-go-version.sh}

expect_success() {
	version=$1
	if ! "$checker" "$version" >/dev/null 2>&1; then
		echo "expected version to pass: $version" >&2
		exit 1
	fi
}

expect_failure() {
	version=$1
	if "$checker" "$version" >/dev/null 2>&1; then
		echo "expected version to fail: $version" >&2
		exit 1
	fi
}

expect_success go1.26
expect_success go1.26rc1
expect_success go1.26.5
expect_success go1.27beta2
expect_success go2.0
expect_failure go1.25.9
expect_failure go0.99
expect_failure 1.26.0
expect_failure go1
expect_failure go1.x
expect_failure go1.26-not-a-version

echo "Go version checker tests: OK"
