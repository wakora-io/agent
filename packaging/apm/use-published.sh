#!/bin/bash
set -euo pipefail
NODE="${1:?usage: use-published.sh <node> <file>...}"
shift
DIR=/var/lib/wakora-release/apm
HERE="$(cd "$(dirname "$0")" && pwd)"
HAVE="$(ssh -n root@"$NODE" "ls -1 $DIR")"
ALLOW="$(tr -d '\r' < "$HERE/republish.txt" 2>/dev/null | grep -v '^[[:space:]]*$' || true)"
for f in "$@"; do
  name="$(basename "$f")"
  if grep -qxF "$name" <<<"$HAVE" && ! grep -qxF "$name" <<<"$ALLOW"; then
    scp -q -O root@"$NODE":"$DIR/$name" "$f"
    echo "testing the published $name"
  fi
done
