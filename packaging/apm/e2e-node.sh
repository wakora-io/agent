#!/bin/bash
set -euo pipefail
ARTDIR="${1:?usage: e2e-node.sh <artifact-dir>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ARTDIR="$(cd "$ARTDIR" && pwd)"
docker run --rm --security-opt apparmor=unconfined \
  -v "$HERE":/in:ro -v "$ARTDIR":/art:ro node:18-bookworm bash /in/inner-e2e-node.sh
