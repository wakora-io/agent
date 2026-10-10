pinned() {
  local d
  d="$(awk -v t="$1" '$1 == t {print $2}' "$(dirname "${BASH_SOURCE[0]}")/images.lock")"
  if [ -z "$d" ]; then
    echo "no pinned digest for $1 in images.lock - add it with bump-images.sh" >&2
    return 1
  fi
  printf '%s@%s\n' "$1" "$d"
}
