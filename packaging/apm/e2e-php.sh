#!/bin/bash
set -euo pipefail
ARTDIR="${1:?usage: e2e-php.sh <artifact-dir> <php-minor>}"
VER="${2:?usage: e2e-php.sh <artifact-dir> <php-minor>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ARTDIR="$(cd "$ARTDIR" && pwd)"
ARCH=$(uname -m)
case "$ARCH" in
  x86_64) ARCH=amd64 ;;
  aarch64) ARCH=arm64 ;;
esac

docker run --rm --security-opt apparmor=unconfined \
  -v "$HERE":/in:ro -v "$ARTDIR":/art:ro "php:$VER-cli" \
  sh /in/inner-e2e.sh "opentelemetry-$VER-nts-$ARCH-glibc.so"
