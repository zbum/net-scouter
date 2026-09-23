#!/usr/bin/env bash
# Upload dist/deb/latest.env to the Nexus apt-hosted repository and wait until
# the stable/main package list contains that deb. Credentials stay in a
# mode-600 netrc file.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

: "${NEXUS_USER:?set NEXUS_USER}"
: "${NEXUS_PASS:?set NEXUS_PASS}"
NEXUS_URL="${NEXUS_URL:-https://nexus.manty.co.kr}"
NEXUS_APT_REPO="${NEXUS_APT_REPO:-apt-hosted}"
NEXUS_APT_DISTRIBUTION="${NEXUS_APT_DISTRIBUTION:-stable}"
NEXUS_URL=${NEXUS_URL%/}

"$(dirname "$0")/build-deb.sh"

# shellcheck disable=SC1091
source dist/deb/latest.env
deb_file="$root/$DEB_PATH"
if [[ ! -f "$deb_file" ]]; then
	echo "missing $deb_file" >&2
	exit 1
fi

name=$(basename "$deb_file")
repo_url="$NEXUS_URL/repository/$NEXUS_APT_REPO"
upload_url="$NEXUS_URL/service/rest/v1/components?repository=$NEXUS_APT_REPO"
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
	-X POST \
	-H "accept: application/json" \
	-F "apt.asset=@${deb_file}" \
	"$upload_url"
echo

echo "waiting for apt metadata to list $name"
packages_base="$repo_url/dists/$NEXUS_APT_DISTRIBUTION/main/binary-$DEB_ARCH"
deadline=$((SECONDS + 90))
found=0
while ((SECONDS < deadline)); do
	plain=$(curl --fail --silent --show-error --netrc-file "$netrc" \
		"$packages_base/Packages" 2>/dev/null || true)
	compressed=$(curl --fail --silent --show-error --netrc-file "$netrc" \
		"$packages_base/Packages.gz" 2>/dev/null | gzip -dc 2>/dev/null || true)
	if printf '%s\n%s\n' "$plain" "$compressed" | grep -q "$name"; then
		found=1
		break
	fi
	sleep 3
done

if [[ "$found" -ne 1 ]]; then
	echo "uploaded, but apt metadata does not list $name yet" >&2
	echo "expected list: $packages_base/Packages" >&2
	echo "repository distribution must be $NEXUS_APT_DISTRIBUTION" >&2
	exit 1
fi

cat <<EOF
apt metadata contains $name

Install on Ubuntu. Use the public half of the key configured on $NEXUS_APT_REPO:

sudo install -d -m 0755 /etc/apt/keyrings
sudo gpg --dearmor -o /etc/apt/keyrings/manty-apt.gpg < public.gpg.key
echo 'deb [signed-by=/etc/apt/keyrings/manty-apt.gpg] $repo_url/ $NEXUS_APT_DISTRIBUTION main' \\
  | sudo tee /etc/apt/sources.list.d/net-scouter.list
sudo apt update
sudo apt install net-scouter

Nexus signs the apt metadata, not the package. The package does not enable the service.
Edit /etc/net-scouter/net-scouter.yaml before starting net-scouter.service.
EOF
