#!/bin/bash
set -euo pipefail
VER="${1:?usage: build-node.sh <otel-node-version> <outdir>}"
OUT="${2:?usage: build-node.sh <otel-node-version> <outdir>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/pinned.sh"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
IMG="$(pinned node:22-bookworm)"
docker run --rm --security-opt apparmor=unconfined \
  -v "$HERE":/in:ro -v "$OUT":/out "$IMG" bash /in/inner-node.sh "$VER"
