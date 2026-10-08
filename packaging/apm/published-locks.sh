#!/bin/bash
set -euo pipefail
NODE="${1:?usage: published-locks.sh <node> <outdir>}"
OUT="${2:?usage: published-locks.sh <node> <outdir>}"
DIR=/var/lib/wakora-release/apm
mkdir -p "$OUT"
for b in opentelemetry-php-sdk opentelemetry-php-sdk81; do
  if ssh -n root@"$NODE" "test -f $DIR/$b.tar.gz"; then
    mkdir -p "$OUT/$b"
    scp -q -O root@"$NODE":"$DIR/$b.tar.gz" "$OUT/$b.tar.gz"
    tar -C "$OUT/$b" -xzf "$OUT/$b.tar.gz" composer.json composer.lock
    rm -f "$OUT/$b.tar.gz"
    echo "pinned $b to the published composer.lock"
  fi
done
