#!/bin/bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
while read -r tag _; do
  [ -z "$tag" ] && continue
  docker pull -q "$tag" >/dev/null
  printf '%s %s\n' "$tag" "$(docker inspect --format '{{index .RepoDigests 0}}' "$tag" | cut -d@ -f2)" >> "$TMP"
done < "$HERE/images.lock"
cp "$TMP" "$HERE/images.lock"
cat "$HERE/images.lock"
