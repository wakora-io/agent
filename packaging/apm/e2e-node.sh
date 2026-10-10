#!/bin/bash
set -euo pipefail
ARTDIR="${1:?usage: e2e-node.sh <artifact-dir>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/pinned.sh"
ARTDIR="$(cd "$ARTDIR" && pwd)"
IMG="$(pinned node:18-bookworm)"
docker run --rm --security-opt apparmor=unconfined \
  -v "$HERE":/in:ro -v "$ARTDIR":/art:ro "$IMG" bash /in/inner-e2e-node.sh
