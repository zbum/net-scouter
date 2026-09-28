#!/usr/bin/env bash
# Build one net-scouter RPM for GOARCH (amd64 by default).
# The Go binary is cross-compiled on the host. BPF and rpmbuild run in
# rockylinux:8 because the public 8.10 tag is not published and Apple clang
# has no BPF target. The image is not privileged and does not attach programs.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

GOARCH="${GOARCH:-amd64}"
case "$GOARCH" in
amd64)
	RPM_ARCH=x86_64
	BPF_ARCH=x86
	;;
arm64)
	RPM_ARCH=aarch64
	BPF_ARCH=arm64
	;;
*)
	echo "unsupported GOARCH=$GOARCH (use amd64 or arm64)" >&2
	exit 1
	;;
esac

RELEASE="${RPM_RELEASE:-1}"
if ! [[ "$RELEASE" =~ ^[0-9A-Za-z._]+$ ]]; then
	echo "invalid RPM_RELEASE=$RELEASE" >&2
	exit 1
fi
VERSION=$("$root/scripts/package-version.sh")
if ! [[ "$VERSION" =~ ^[0-9A-Za-z._+~]+$ ]]; then
	echo "invalid RPM version: $VERSION" >&2
	exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
	echo "docker is required to compile the BPF object and build the RPM" >&2
	exit 1
fi

make build-linux "GOARCH=$GOARCH"

image="${RPM_BUILD_IMAGE:-net-scouter-rpm-build:8}"
platform="${RPM_BUILD_PLATFORM:-linux/amd64}"
"$root/scripts/ensure-build-image.sh" "$image" "$root/deploy/docker/rpm-build.Dockerfile" "$platform"
echo "building BPF and RPM in $image ($platform) for $RPM_ARCH"

docker run --rm -i \
	--platform "$platform" \
	-u "$(id -u):$(id -g)" \
	-e HOME=/tmp \
	-e "BPF_ARCH=$BPF_ARCH" \
	-e "VERSION=$VERSION" \
	-e "RELEASE=$RELEASE" \
	-e "RPM_ARCH=$RPM_ARCH" \
	-e "GOARCH=$GOARCH" \
	-v "$root:/work" \
	-w /work \
	"$image" \
	bash -s <<'EOS'
set -euo pipefail
make build-bpf "BPF_ARCH=$BPF_ARCH" BPF_CPU=v1

top=$(mktemp -d)
mkdir -p "$top"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
cp "dist/net-scouter-linux-$GOARCH" "$top/SOURCES/net-scouter"
cp dist/flow.bpf.o "$top/SOURCES/flow.bpf.o"
cp configs/net-scouter.yaml "$top/SOURCES/net-scouter.yaml"
cp LICENSE "$top/SOURCES/LICENSE"
sed 's#/usr/local/bin/net-scouter#/usr/bin/net-scouter#' \
	deploy/systemd/net-scouter.service > "$top/SOURCES/net-scouter.service"
cp deploy/rpm/net-scouter.spec "$top/SPECS/net-scouter.spec"

rpmbuild -bb \
	--define "_topdir $top" \
	--define "ns_version $VERSION" \
	--define "ns_release $RELEASE" \
	--define "ns_arch $RPM_ARCH" \
	--target "$RPM_ARCH" \
	"$top/SPECS/net-scouter.spec"

mkdir -p /work/dist/rpm
find "$top/RPMS" -type f -name '*.rpm' -exec cp -f {} /work/dist/rpm/ \;
EOS

rpm_path="dist/rpm/net-scouter-${VERSION}-${RELEASE}.${RPM_ARCH}.rpm"
if [[ ! -f "$rpm_path" ]]; then
	echo "rpmbuild did not produce $rpm_path" >&2
	find dist/rpm -type f -name '*.rpm' -print >&2 || true
	exit 1
fi
cat > dist/rpm/latest.env <<EOF
VERSION=$VERSION
RELEASE=$RELEASE
RPM_ARCH=$RPM_ARCH
RPM_PATH=$rpm_path
EOF
rpm_name=$(basename "$rpm_path")
if command -v sha256sum >/dev/null 2>&1; then
	(cd dist/rpm && sha256sum "$rpm_name" > "$rpm_name.sha256")
else
	(cd dist/rpm && shasum -a 256 "$rpm_name" > "$rpm_name.sha256")
fi
echo "built $rpm_path"
