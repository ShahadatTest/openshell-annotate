#!/usr/bin/env bash
# Build the local image openshell-annotate:dev. Never pushes.
#   OPENSHELL_SRC   OpenShell checkout providing openshell-policy-schema (default ~/src/OpenShell)
#   IMAGE           tag (default openshell-annotate:dev)
# Cargo.toml pins openshell-policy-schema to a git tag of that checkout. A BuildKit named context drops `.git`
# (OpenShell's .dockerignore excludes it), so we hand Docker a shallow bare clone of just that tag instead.
set -euo pipefail
cd "$(dirname "$0")/.."
SRC="${OPENSHELL_SRC:-$HOME/src/OpenShell}"
IMAGE="${IMAGE:-openshell-annotate:dev}"
[ -d "$SRC/.git" ] || { echo "OpenShell checkout not found at $SRC (set OPENSHELL_SRC)" >&2; exit 1; }
TAG="$(sed -n 's/^openshell-policy-schema = .*tag = "\([^"]*\)".*/\1/p' Cargo.toml)"
[ -n "$TAG" ] || { echo "cannot read the openshell-policy-schema tag from Cargo.toml" >&2; exit 1; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
git clone --quiet --bare --depth 1 --branch "$TAG" "file://$SRC" "$TMP/OpenShell"
DOCKER_BUILDKIT=1 docker build --build-context "openshell=$TMP/OpenShell" -t "$IMAGE" "$@" .
echo "built $IMAGE"
docker image inspect "$IMAGE" --format 'size: {{.Size}} bytes'
