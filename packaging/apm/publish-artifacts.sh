#!/bin/bash
set -euo pipefail
NODE="${1:?usage: publish-artifacts.sh <node> <file>...}"
shift
DIR=/var/lib/wakora-release/apm
HERE="$(cd "$(dirname "$0")" && pwd)"
ssh -n root@"$NODE" "mkdir -p $DIR"
HAVE="$(ssh -n root@"$NODE" "ls -1 $DIR")"
ALLOW="$(grep -v '^[[:space:]]*$' "$HERE/republish.txt" 2>/dev/null || true)"
for f in "$@"; do
  name="$(basename "$f")"
  if grep -qxF "$name" <<<"$HAVE" && ! grep -qxF "$name" <<<"$ALLOW"; then
    echo "frozen: $name stays as published"
    continue
  fi
  scp -q -O "$f" root@"$NODE":"$DIR/.incoming-$name"
  ssh -n root@"$NODE" "mv -f $DIR/.incoming-$name $DIR/$name"
  echo "published: $name"
done
