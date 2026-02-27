#!/bin/bash
# Redistribute the official dotnet-trace single-file binaries into the signed APM
# channel. aka.ms serves the latest diagnostics release from the MS CDN over HTTPS;
# no upstream checksum file exists for these links, so integrity for the fleet is
# anchored by OUR signed manifest (sha256 computed at publish, ed25519 on .81).
set -euo pipefail
OUT="$1"
mkdir -p "$OUT"

declare -A MAP=(
  [dotnet-trace-windows-amd64.exe]=win-x64
  [dotnet-trace-windows-arm64.exe]=win-arm64
  [dotnet-trace-linux-glibc-amd64]=linux-x64
  [dotnet-trace-linux-glibc-arm64]=linux-arm64
  [dotnet-trace-linux-musl-amd64]=linux-musl-x64
  [dotnet-trace-linux-musl-arm64]=linux-musl-arm64
)

for name in "${!MAP[@]}"; do
  src="${MAP[$name]}"
  echo "fetching $name (aka.ms/dotnet-trace/$src)"
  curl -fsSL "https://aka.ms/dotnet-trace/$src" -o "$OUT/$name"
  chmod 0755 "$OUT/$name"
done

chmod +x "$OUT/dotnet-trace-linux-glibc-amd64"
"$OUT/dotnet-trace-linux-glibc-amd64" --version | head -1 > "$OUT/dotnet-trace.version"
cat "$OUT/dotnet-trace.version"
ls -la "$OUT"
