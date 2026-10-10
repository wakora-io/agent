install_pinned() {
  tool="$1"
  url="$2"
  dest="$3"
  ver="$(awk -v t="$tool" '$1 == t {print $2}' /in/tools.lock)"
  sum="$(awk -v t="$tool" '$1 == t {print $3}' /in/tools.lock)"
  if [ -z "$ver" ] || [ -z "$sum" ]; then
    echo "no pinned $tool in tools.lock" >&2
    exit 1
  fi
  url="$(printf '%s' "$url" | sed "s/@VERSION@/$ver/g")"
  php -r "copy('$url', '$dest');"
  echo "$sum  $dest" | sha256sum -c - >/dev/null
  chmod +x "$dest"
}
