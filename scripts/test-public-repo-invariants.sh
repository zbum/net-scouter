#!/usr/bin/env bash
set -euo pipefail

test -s LICENSE
grep -q '^module github.com/zbum/net-scouter$' go.mod
if git grep -n -E \
  'github.com/example/net-scouter|/Users/nhn|^[[:space:]]*gpgcheck=0[[:space:]]*$' \
  -- ':!docs/features/**' ':!scripts/test-public-repo-invariants.sh'; then
  echo "public repository metadata contains a placeholder module, unsafe RPM guidance, or local path" >&2
  exit 1
fi
grep -q '^\.omc/\*\*$' .gitignore
grep -q '^!\.omc/skills/\*\*$' .gitignore
grep -q 'example-warning:.*Privileged host-observer example' deploy/kubernetes/daemonset.yaml
grep -q 'Required: replace this non-runnable placeholder with a trusted digest' deploy/kubernetes/daemonset.yaml
grep -q 'registry.example/net-scouter@sha256:REPLACE_WITH_TRUSTED_IMAGE_DIGEST' deploy/kubernetes/daemonset.yaml
if grep -q 'hostPID:' deploy/kubernetes/daemonset.yaml; then
  echo "Kubernetes example must not request the host process namespace" >&2
  exit 1
fi
grep -q 'cp LICENSE "$top/SOURCES/LICENSE"' scripts/build-rpm.sh
grep -q '%license %{_licensedir}/%{name}/LICENSE' deploy/rpm/net-scouter.spec
grep -q 'LICENSE "$stage/usr/share/doc/net-scouter/copyright"' scripts/build-deb.sh
test "$(grep -R -l '\.sha256' scripts/build-deb.sh scripts/build-rpm.sh scripts/publish-deb.sh scripts/publish-rpm.sh | wc -l | tr -d ' ')" -eq 4

echo "Public repository invariants: OK"
