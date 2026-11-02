#!/usr/bin/env bash
# Build the local image (default tag openshell-annotate:dev). Never pushes.
#   IMAGE   tag to build (default openshell-annotate:dev)
# Extra arguments are passed to `docker build`.
set -euo pipefail
cd "$(dirname "$0")/.."
IMAGE="${IMAGE:-openshell-annotate:dev}"
DOCKER_BUILDKIT=1 docker build -t "$IMAGE" "$@" .
echo "built $IMAGE"
docker image inspect "$IMAGE" --format 'size: {{.Size}} bytes'
