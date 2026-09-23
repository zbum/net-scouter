#!/usr/bin/env bash
# Build a local toolchain image when it is not already present.
# Usage: ensure-build-image.sh IMAGE DOCKERFILE PLATFORM
set -euo pipefail

image=${1:?image}
dockerfile=${2:?dockerfile}
platform=${3:?platform}

if docker image inspect "$image" >/dev/null 2>&1; then
	exit 0
fi

echo "building $image once; later package builds reuse it" >&2
docker build --platform "$platform" -t "$image" -f "$dockerfile" "$(dirname "$dockerfile")"
