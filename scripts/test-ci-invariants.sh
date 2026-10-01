#!/usr/bin/env bash
set -euo pipefail

jenkinsfile=Jenkinsfile
makefile=Makefile
loader=scripts/verify-bpf-load.sh
service=deploy/systemd/net-scouter.service

grep -q "name: 'RUN_KERNEL_VERIFIERS', defaultValue: false" "$jenkinsfile"
grep -q "NEXUS_CREDENTIALS_ID = 'nexus-credentials'" "$jenkinsfile"
grep -Fq "NEXUS_URL = 'https://nexus.manty.co.kr'" "$jenkinsfile"
grep -q "agent { label 'linux && amd64 && ubuntu-build' }" "$jenkinsfile"
grep -q "agent { label 'linux && amd64 && rocky-build' }" "$jenkinsfile"
grep -q "sh 'make deb'" "$jenkinsfile"
grep -q "sh 'make rpm'" "$jenkinsfile"
grep -q 'for tool in git go make docker file clang curl gzip' "$jenkinsfile"
test "$(grep -c "sh 'make check-go-version'" "$jenkinsfile")" -eq 2
grep -q "sh 'docker version'" "$jenkinsfile"
grep -q "stage('Publish release packages to Nexus')" "$jenkinsfile"
grep -q "credentialsId: env.NEXUS_CREDENTIALS_ID" "$jenkinsfile"
grep -q "sh 'SKIP_PACKAGE_BUILD=1 ./scripts/publish-deb.sh'" "$jenkinsfile"
grep -q "sh 'SKIP_PACKAGE_BUILD=1 ./scripts/publish-rpm.sh'" "$jenkinsfile"
grep -q "env.BRANCH_NAME?.startsWith('release/')" "$jenkinsfile"
grep -q "release branch .* does not match VERSION" "$jenkinsfile"
grep -q 'currentBuild.displayName = "#${env.BUILD_NUMBER} v${releaseVersion}"' "$jenkinsfile"
grep -q "stage('Reject untrusted change requests')" "$jenkinsfile"
test "$(grep -c 'not { changeRequest() }' "$jenkinsfile")" -eq 3
test "$(grep -c '/usr/local/sbin/net-scouter-verify-bpf-load' "$jenkinsfile")" -eq 2
if grep -Eq 'params\.(NEXUS_CREDENTIALS_ID|UBUNTU_BUILD_NODE_LABEL|ROCKY_BUILD_NODE_LABEL|UBUNTU_VERIFIER_LABEL|ROCKY_VERIFIER_LABEL)' "$jenkinsfile"; then
  echo "security-sensitive credentials and node labels must not be build parameters" >&2
  exit 1
fi
if grep -q 'sudo -n make' "$jenkinsfile"; then
  echo "CI must not execute repository-controlled build logic through sudo" >&2
  exit 1
fi
grep -q 'ROCKY_IMAGE ?= rockylinux:8' "$makefile"
grep -q '/artifacts/$(BINARY)-linux-amd64 flows --help' "$makefile"
grep -q 'CGO_ENABLED=0 GOOS=linux GOARCH=' "$makefile"
grep -q '^check-go-version:' "$makefile"
grep -q '^test-ci: check-go-version ' "$makefile"
grep -q 'bpftool prog loadall "$object" "$pin_dir"$' "$loader"
grep -q 'trap cleanup EXIT INT TERM' "$loader"
grep -q 'pin_dir=$(mktemp -d "${pin_root}/net-scouter-verify.XXXXXXXX")' "$loader"
grep -q 'owns_pin_dir=1' "$loader"
grep -q '\[\[ "$owns_pin_dir" -eq 1' "$loader"
grep -q '^StandardOutput=null$' "$service"
grep -q '^StandardError=journal$' "$service"
grep -q '^SyslogIdentifier=net-scouter$' "$service"
grep -q '^LogRateLimitIntervalSec=30s$' "$service"
grep -q '^LogRateLimitBurst=100$' "$service"

if grep -Eqi '\b(tc|ip) (qdisc|filter|link)|bpftool net attach|bpftool prog attach' "$loader" "$jenkinsfile"; then
  echo "CI verifier gate must never attach programs or alter interfaces" >&2
  exit 1
fi
if grep -Eq -- '--privileged|--network host|--cap-add' "$makefile" "$jenkinsfile"; then
  echo "Rocky userspace check must stay unprivileged and isolated" >&2
  exit 1
fi
if grep -q '^build-linux:.*dist/' "$makefile"; then
  echo "build-linux must not reuse a stale dist artifact" >&2
  exit 1
fi

echo "CI safety invariants: OK"
