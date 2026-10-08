#!/bin/bash
set -euo pipefail
NODE="${1:?usage: transplant-bootstrap.sh <node> <bundle.tar.gz>...}"
shift
DIR=/var/lib/wakora-release/apm
HERE="$(cd "$(dirname "$0")" && pwd)"
ALLOW="$(tr -d '\r' < "$HERE/republish.txt" 2>/dev/null | grep -v '^[[:space:]]*$' || true)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
for f in "$@"; do
  name="$(basename "$f")"
  grep -qxF "$name" <<<"$ALLOW" || continue
  ssh -n root@"$NODE" "test -f $DIR/$name" || continue
  rm -rf "$WORK/pub" "$WORK/new"
  mkdir -p "$WORK/pub" "$WORK/new"
  scp -q -O root@"$NODE":"$DIR/$name" "$WORK/pub.tgz"
  tar -C "$WORK/pub" -xzf "$WORK/pub.tgz"
  tar -C "$WORK/new" -xzf "$f" wakora-otel.php
  cp "$WORK/new/wakora-otel.php" "$WORK/pub/wakora-otel.php"
  tar -C "$WORK/pub" -czf "$f" composer.json composer.lock vendor wakora-otel.php
  echo "$name: published vendor kept, only the bootstrap replaced"
done
