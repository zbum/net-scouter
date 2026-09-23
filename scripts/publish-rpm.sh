#!/usr/bin/env bash
# Upload dist/rpm/latest.env to the Nexus yum-hosted repository and wait until
# yum repodata lists that RPM. Credentials stay in a mode-600 netrc file.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

: "${NEXUS_USER:?set NEXUS_USER}"
: "${NEXUS_PASS:?set NEXUS_PASS}"
NEXUS_URL="${NEXUS_URL:-https://nexus.manty.co.kr}"
NEXUS_YUM_REPO="${NEXUS_YUM_REPO:-yum-hosted}"
NEXUS_URL=${NEXUS_URL%/}

"$(dirname "$0")/build-rpm.sh"

# shellcheck disable=SC1091
source dist/rpm/latest.env
rpm_file="$root/$RPM_PATH"
if [[ ! -f "$rpm_file" ]]; then
	echo "missing $rpm_file" >&2
	exit 1
fi

name=$(basename "$rpm_file")
upload_url="$NEXUS_URL/repository/$NEXUS_YUM_REPO/net-scouter/$name"
repo_url="$NEXUS_URL/repository/$NEXUS_YUM_REPO/net-scouter/"
host=${NEXUS_URL#*://}
host=${host%%/*}

netrc=$(mktemp)
chmod 600 "$netrc"
trap 'rm -f "$netrc"' EXIT
cat > "$netrc" <<EOF
machine $host
login $NEXUS_USER
password $NEXUS_PASS
EOF

echo "uploading $name"
curl --fail --silent --show-error \
	--netrc-file "$netrc" \
	--upload-file "$rpm_file" \
	"$upload_url"
echo

echo "waiting for yum metadata to list $name"
deadline=$((SECONDS + 90))
found=0
while ((SECONDS < deadline)); do
	if xml=$(curl --fail --silent --show-error --netrc-file "$netrc" \
		"$repo_url/repodata/repomd.xml" 2>/dev/null); then
		href=$(printf '%s\n' "$xml" | sed -n 's/.*href="\([^"]*primary.xml.gz\)".*/\1/p' | head -n 1)
		if [[ -n "$href" ]] && curl --fail --silent --show-error --netrc-file "$netrc" \
			"$repo_url/$href" | gzip -dc | grep -q "$name"; then
			found=1
			break
		fi
	fi
	sleep 3
done

if [[ "$found" -ne 1 ]]; then
	echo "uploaded, but yum metadata does not list $name yet" >&2
	echo "repository: $repo_url" >&2
	exit 1
fi

cat <<EOF
yum metadata contains $name

Install on Rocky or RHEL:

cat >/etc/yum.repos.d/net-scouter.repo <<'REPO'
[net-scouter]
name=net-scouter
baseurl=$repo_url
enabled=1
gpgcheck=0
REPO
dnf clean metadata
dnf install net-scouter

The RPM is not signed. It does not enable the service.
Edit /etc/net-scouter/net-scouter.yaml before starting net-scouter.service.
EOF
