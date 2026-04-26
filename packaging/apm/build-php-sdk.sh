#!/bin/bash
set -euo pipefail
OUT="${1:?usage: build-php-sdk.sh <outdir>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
docker run --rm --security-opt apparmor=unconfined \
  -v "$HERE":/in:ro -v "$OUT":/out php:8.2-cli sh /in/inner-sdk.sh
docker run --rm --security-opt apparmor=unconfined \
  -v "$HERE":/in:ro -v "$OUT":/out php:8.1-cli sh /in/inner-sdk.sh 81
docker run --rm --security-opt apparmor=unconfined \
  -v "$HERE":/in:ro -v "$OUT":/out php:8.2-cli sh /in/inner-scope.sh
