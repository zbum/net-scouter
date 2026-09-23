#!/usr/bin/env bash
set -euo pipefail

jenkinsfile=Jenkinsfile
makefile=Makefile
loader=scripts/verify-bpf-load.sh

grep -q "name: 'RUN_KERNEL_VERIFIERS', defaultValue: false" "$jenkinsfile"
grep -q "name: 'UBUNTU_BUILD_NODE_LABEL'.*ubuntu-build" "$jenkinsfile"
grep -q "name: 'ROCKY_BUILD_NODE_LABEL'.*rocky-build" "$jenkinsfile"
grep -q "name: 'NEXUS_CREDENTIALS_ID'.*defaultValue: 'nexus-credentials'" "$jenkinsfile"
grep -q "agent { label \"\${params.UBUNTU_BUILD_NODE_LABEL}\" }" "$jenkinsfile"
grep -q "agent { label \"\${params.ROCKY_BUILD_NODE_LABEL}\" }" "$jenkinsfile"
grep -q "sh 'make deb'" "$jenkinsfile"
grep -q "sh 'make rpm'" "$jenkinsfile"
grep -q 'for tool in git go make docker file clang curl gzip' "$jenkinsfile"
grep -q "sh 'docker version'" "$jenkinsfile"
grep -q "stage('Publish release packages to Nexus')" "$jenkinsfile"
grep -q "credentialsId: params.NEXUS_CREDENTIALS_ID" "$jenkinsfile"
grep -q "sh 'SKIP_PACKAGE_BUILD=1 ./scripts/publish-deb.sh'" "$jenkinsfile"
grep -q "sh 'SKIP_PACKAGE_BUILD=1 ./scripts/publish-rpm.sh'" "$jenkinsfile"
grep -q "env.BRANCH_NAME?.startsWith('release/')" "$jenkinsfile"
grep -q "release branch .* does not match VERSION" "$jenkinsfile"
grep -q 'currentBuild.displayName = "#${env.BUILD_NUMBER} v${releaseVersion}"' "$jenkinsfile"
grep -q 'ROCKY_IMAGE ?= rockylinux:8' "$makefile"
grep -q '/artifacts/$(BINARY)-linux-amd64 flows --help' "$makefile"
grep -q 'CGO_ENABLED=0 GOOS=linux GOARCH=' "$makefile"
grep -q 'bpftool prog loadall "$object" "$pin_dir"$' "$loader"
grep -q 'trap cleanup EXIT INT TERM' "$loader"
grep -q 'pin_dir=$(mktemp -d "${pin_root}/net-scouter-verify.XXXXXXXX")' "$loader"
grep -q 'owns_pin_dir=1' "$loader"
grep -q '\[\[ "$owns_pin_dir" -eq 1' "$loader"

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
