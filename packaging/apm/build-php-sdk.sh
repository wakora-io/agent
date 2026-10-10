#!/bin/bash
set -euo pipefail
OUT="${1:?usage: build-php-sdk.sh <outdir> [published-lock-dir]}"
PUB="${2:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/pinned.sh"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
PHP82="$(pinned php:8.2-cli)"
PHP81="$(pinned php:8.1-cli)"
pin() {
  if [ -n "$PUB" ] && [ -f "$PUB/$1/composer.lock" ]; then
    echo "-v $(cd "$PUB/$1" && pwd):/pub:ro"
  fi
}
docker run --rm --security-opt apparmor=unconfined $(pin opentelemetry-php-sdk) \
  -v "$HERE":/in:ro -v "$OUT":/out "$PHP82" sh /in/inner-sdk.sh
docker run --rm --security-opt apparmor=unconfined $(pin opentelemetry-php-sdk81) \
  -v "$HERE":/in:ro -v "$OUT":/out "$PHP81" sh /in/inner-sdk.sh 81
docker run --rm --security-opt apparmor=unconfined \
  -v "$HERE":/in:ro -v "$OUT":/out "$PHP82" sh /in/inner-scope.sh
