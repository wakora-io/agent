#!/bin/bash
set -euo pipefail
EXTVER="${1:?usage: build-php.sh <ext-version> <outdir> <line>}"
OUT="${2:?usage: build-php.sh <ext-version> <outdir> <line>}"
LINE="${3:?usage: build-php.sh <ext-version> <outdir> <line>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

ARCH=$(uname -m)
case "$ARCH" in
  x86_64) ARCH=amd64 ;;
  aarch64) ARCH=arm64 ;;
esac

for ver in 8.1 8.2 8.3 8.4 8.5; do
  for ts in nts zts; do
    for libc in glibc musl; do
      img="php:$ver-cli"
      [ "$ts" = zts ] && img="php:$ver-zts"
      [ "$libc" = musl ] && img="$img-alpine"
      name="opentelemetry-$LINE-$ver-$ts-$ARCH-$libc.so"
      docker run --rm --security-opt apparmor=unconfined \
        -v "$HERE":/in:ro -v "$OUT":/out "$img" sh /in/inner-php.sh "$EXTVER" "$name"
      echo "built $name (ext $EXTVER, $img)"
    done
  done
done
