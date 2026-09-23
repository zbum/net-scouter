#!/usr/bin/env bash
# Build one net-scouter .deb for GOARCH (amd64 by default).
# The Go binary is cross-compiled on the host. BPF and dpkg-deb run in
# Ubuntu 22.04 because Apple clang has no BPF target. The container is not
# privileged and does not attach programs.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

GOARCH="${GOARCH:-amd64}"
case "$GOARCH" in
amd64)
	DEB_ARCH=amd64
	BPF_ARCH=x86
	;;
arm64)
	DEB_ARCH=arm64
	BPF_ARCH=arm64
	;;
*)
	echo "unsupported GOARCH=$GOARCH (use amd64 or arm64)" >&2
	exit 1
	;;
esac

REVISION="${DEB_REVISION:-1}"
if ! [[ "$REVISION" =~ ^[0-9A-Za-z.+~]+$ ]]; then
	echo "invalid DEB_REVISION=$REVISION" >&2
	exit 1
fi
PACKAGE_VERSION=$("$root/scripts/package-version.sh")
if ! [[ "$PACKAGE_VERSION" =~ ^[0-9][0-9A-Za-z.+~]*$ ]]; then
	echo "invalid package version: $PACKAGE_VERSION" >&2
	exit 1
fi
DEB_VERSION="${PACKAGE_VERSION}-${REVISION}"

if ! command -v docker >/dev/null 2>&1; then
	echo "docker is required to compile the BPF object and build the deb" >&2
	exit 1
fi

make build-linux "GOARCH=$GOARCH"

image="${DEB_BUILD_IMAGE:-net-scouter-deb-build:22.04}"
platform="${DEB_BUILD_PLATFORM:-linux/amd64}"
"$root/scripts/ensure-build-image.sh" "$image" "$root/deploy/docker/deb-build.Dockerfile" "$platform"
echo "building BPF and deb in $image ($platform) for $DEB_ARCH"

docker run --rm -i \
	--platform "$platform" \
	-u "$(id -u):$(id -g)" \
	-e HOME=/tmp \
	-e "BPF_ARCH=$BPF_ARCH" \
	-e "DEB_VERSION=$DEB_VERSION" \
	-e "DEB_ARCH=$DEB_ARCH" \
	-e "GOARCH=$GOARCH" \
	-v "$root:/work" \
	-w /work \
	"$image" \
	bash -s <<'EOS'
set -euo pipefail
make build-bpf "BPF_ARCH=$BPF_ARCH" BPF_CPU=v1

stage=$(mktemp -d)
mkdir -p \
	"$stage/DEBIAN" \
	"$stage/usr/bin" \
	"$stage/usr/lib/net-scouter" \
	"$stage/etc/net-scouter" \
	"$stage/usr/lib/systemd/system"
install -m 0755 "dist/net-scouter-linux-$GOARCH" "$stage/usr/bin/net-scouter"
install -m 0644 dist/flow.bpf.o "$stage/usr/lib/net-scouter/flow.bpf.o"
install -m 0644 configs/net-scouter.yaml "$stage/etc/net-scouter/net-scouter.yaml"
sed 's#/usr/local/bin/net-scouter#/usr/bin/net-scouter#' \
	deploy/systemd/net-scouter.service \
	> "$stage/usr/lib/systemd/system/net-scouter.service"
chmod 0644 "$stage/usr/lib/systemd/system/net-scouter.service"
printf '%s\n' /etc/net-scouter/net-scouter.yaml > "$stage/DEBIAN/conffiles"
installed=$(du -sk "$stage/usr" "$stage/etc" | awk '{sum += $1} END {print sum}')
cat > "$stage/DEBIAN/control" <<EOF
Package: net-scouter
Version: $DEB_VERSION
Architecture: $DEB_ARCH
Maintainer: net-scouter <net-scouter@manty.co.kr>
Installed-Size: $installed
Section: net
Priority: optional
Homepage: https://nexus.manty.co.kr/repository/apt-hosted/
Description: Low-overhead IPv4/IPv6 TCP and UDP flow discovery agent
 Observes directional IPv4/IPv6 TCP and UDP flows and keeps packet, byte,
 and local TCP connection counters in a bounded kernel map.
 The package does not enable or start the service.
EOF
cat > "$stage/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
	systemctl daemon-reload >/dev/null 2>&1 || true
fi
EOF
cat > "$stage/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = "remove" ]; then
	systemctl --no-reload disable --now net-scouter.service >/dev/null 2>&1 || true
fi
EOF
cat > "$stage/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
systemctl daemon-reload >/dev/null 2>&1 || true
if [ "$1" = "upgrade" ]; then
	systemctl try-restart net-scouter.service >/dev/null 2>&1 || true
fi
EOF
chmod 0755 "$stage/DEBIAN/postinst" "$stage/DEBIAN/prerm" "$stage/DEBIAN/postrm"

mkdir -p /work/dist/deb
out="/work/dist/deb/net-scouter_${DEB_VERSION}_${DEB_ARCH}.deb"
dpkg-deb --root-owner-group --build "$stage" "$out"
EOS

deb_path="dist/deb/net-scouter_${DEB_VERSION}_${DEB_ARCH}.deb"
if [[ ! -f "$deb_path" ]]; then
	echo "dpkg-deb did not produce $deb_path" >&2
	find dist/deb -type f -name '*.deb' -print >&2 || true
	exit 1
fi
cat > dist/deb/latest.env <<EOF
DEB_VERSION=$DEB_VERSION
DEB_ARCH=$DEB_ARCH
DEB_PATH=$deb_path
EOF
echo "built $deb_path"
