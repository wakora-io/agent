#!/bin/bash
set -euo pipefail
VER="${1:?usage: build-node.sh <otel-node-version> <outdir>}"
OUT="${2:?usage: build-node.sh <otel-node-version> <outdir>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
docker run --rm --security-opt apparmor=unconfined \
  -v "$HERE":/in:ro -v "$OUT":/out node:22-bookworm bash /in/inner-node.sh "$VER"
