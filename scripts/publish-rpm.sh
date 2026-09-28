#!/usr/bin/env bash
# Upload dist/rpm/latest.env to the Nexus yum-hosted repository and wait until
# yum repodata lists that RPM. Credentials stay in a mode-600 netrc file.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

: "${NEXUS_USER:?set NEXUS_USER}"
: "${NEXUS_PASS:?set NEXUS_PASS}"
: "${NEXUS_URL:?set NEXUS_URL to the package repository base URL}"
NEXUS_YUM_REPO="${NEXUS_YUM_REPO:-yum-hosted}"
NEXUS_URL=${NEXUS_URL%/}

if [[ "${SKIP_PACKAGE_BUILD:-0}" != "1" ]]; then
	"$(dirname "$0")/build-rpm.sh"
fi

# shellcheck disable=SC1091
source dist/rpm/latest.env
rpm_file="$root/$RPM_PATH"
if [[ ! -f "$rpm_file" ]]; then
	echo "missing $rpm_file" >&2
	exit 1
fi
checksum_file="$rpm_file.sha256"
if [[ ! -f "$checksum_file" ]]; then
	echo "missing $checksum_file" >&2
	exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
	(cd "$(dirname "$rpm_file")" && sha256sum --check "$(basename "$checksum_file")")
else
	(cd "$(dirname "$rpm_file")" && shasum -a 256 --check "$(basename "$checksum_file")")
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

The RPM is currently unsigned. Do not publish installation instructions that
disable signature verification. Distribute the RPM with its generated
.sha256 file over a
trusted channel, or configure RPM signing and publish the signing key before
enabling repository installation.
EOF
