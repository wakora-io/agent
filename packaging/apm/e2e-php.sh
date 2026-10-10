#!/bin/bash
set -euo pipefail
ARTDIR="${1:?usage: e2e-php.sh <artifact-dir> <php-minor> <line>}"
VER="${2:?usage: e2e-php.sh <artifact-dir> <php-minor> <line>}"
LINE="${3:?usage: e2e-php.sh <artifact-dir> <php-minor> <line>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/pinned.sh"
ARTDIR="$(cd "$ARTDIR" && pwd)"
IMG="$(pinned "php:$VER-cli")"
ARCH=$(uname -m)
case "$ARCH" in
  x86_64) ARCH=amd64 ;;
  aarch64) ARCH=arm64 ;;
esac

docker run --rm --security-opt apparmor=unconfined \
  -v "$HERE":/in:ro -v "$ARTDIR":/art:ro "$IMG" \
  sh /in/inner-e2e.sh "opentelemetry-$LINE-$VER-nts-$ARCH-glibc.so"
