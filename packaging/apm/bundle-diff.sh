#!/bin/bash
set -euo pipefail
NODE="${1:?usage: bundle-diff.sh <node> <bundle.tar.gz>...}"
shift
DIR=/var/lib/wakora-release/apm
HERE="$(cd "$(dirname "$0")" && pwd)"
ALLOW="$(tr -d '\r' < "$HERE/republish.txt" 2>/dev/null | grep -v '^[[:space:]]*$' || true)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fail=0
for f in "$@"; do
  name="$(basename "$f")"
  grep -qxF "$name" <<<"$ALLOW" || continue
  ssh -n root@"$NODE" "test -f $DIR/$name" || continue
  rm -rf "$WORK/old" "$WORK/new"
  mkdir -p "$WORK/old" "$WORK/new"
  scp -q -O root@"$NODE":"$DIR/$name" "$WORK/old.tgz"
  tar -C "$WORK/old" -xzf "$WORK/old.tgz"
  tar -C "$WORK/new" -xzf "$f"
  changed="$(diff -rq "$WORK/old" "$WORK/new" | sed -e "s#$WORK/old/##g" -e "s#$WORK/new/##g" || true)"
  echo "$name differs from the published copy in:"
  echo "${changed:-  nothing}"
  diff "$WORK/old/wakora-otel.php" "$WORK/new/wakora-otel.php" || true
  if [ -n "$(grep -vxF 'Files wakora-otel.php and wakora-otel.php differ' <<<"$changed" || true)" ]; then
    echo "$name: only wakora-otel.php may change in a republished bundle"
    fail=1
  fi
done
exit $fail
