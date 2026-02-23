#!/bin/bash
set -euo pipefail
VER="${1:?usage: build-dotnet.sh <upstream-version> <outdir>}"
OUT="${2:?usage: build-dotnet.sh <upstream-version> <outdir>}"
BASE="https://github.com/open-telemetry/opentelemetry-dotnet-instrumentation/releases/download/$VER"

declare -A MAP=(
  [windows.zip]=opentelemetry-dotnet-windows-amd64
  [linux-glibc-x64.zip]=opentelemetry-dotnet-linux-glibc-amd64
  [linux-musl-x64.zip]=opentelemetry-dotnet-linux-musl-amd64
  [linux-glibc-arm64.zip]=opentelemetry-dotnet-linux-glibc-arm64
  [linux-musl-arm64.zip]=opentelemetry-dotnet-linux-musl-arm64
)

mkdir -p "$OUT"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

curl -fsSL "$BASE/checksums.txt" -o "$work/checksums.txt"
for suffix in "${!MAP[@]}"; do
  asset="opentelemetry-dotnet-instrumentation-$suffix"
  curl -fsSL "$BASE/$asset" -o "$work/$asset"
  (cd "$work" && grep " $asset\$" checksums.txt | sha256sum -c - >/dev/null)
  rm -rf "$work/x" && mkdir "$work/x"
  unzip -q "$work/$asset" -d "$work/x"
  tar -C "$work/x" -czf "$OUT/${MAP[$suffix]}.tar.gz" .
  echo "packed ${MAP[$suffix]}.tar.gz (upstream $asset verified)"
done
