#!/bin/bash
set -euo pipefail
OUT="$1"
mkdir -p "$OUT"

VERSION="dotnet-diagnostics_20260414.1"
BASE="https://download.visualstudio.microsoft.com/download/pr/$VERSION"

PINS="
dotnet-trace-windows-amd64.exe|292221861D5B3052E819B715947662E179183E6570F757C79AAE43F31641FF47/dotnet-trace.exe|7ee81d3b55dfcb3bfa963b7fabb6e15cd426c8d3469325d41e4374d1ebfef369
dotnet-trace-windows-arm64.exe|463C4CAAB8614A66073D2321F24E312B42B5ABC53769BC744C4A61C1DA6AF71B/dotnet-trace.exe|45481f2a9d8137988b4ed41259bc5677a9e63a2909e5dd32a3b433f6aa7bcce2
dotnet-trace-linux-glibc-amd64|2243FF7AD095CE742D70C2276FF3317E2C9CC3E881FF171D0D89C2FBA8B76ABB/dotnet-trace|09c15d9d3febf4b72a4ca6fb30474940b19fa958b47344a9093726de5a4bb924
dotnet-trace-linux-glibc-arm64|4362A506A076616A1D9C05804B4DFC3646B5D57A9518204F1C5CC03238BB41D8/dotnet-trace|fad3f987a48eba4161f549c69b0016702402eb15b8d477a4261acb538151d317
dotnet-trace-linux-musl-amd64|A88783DC0EE9DCD82E2E3492FBB9CAD28BA8F6D6B7F337AA970C3D1344CBC676/dotnet-trace|42da84c2dd573bea7446fb6d7774459e0944c482c00c1e3b02438969230ee1c5
dotnet-trace-linux-musl-arm64|E644492543E2B6887AD6361DB544E610D34313297DB9A515A0313D18435B165D/dotnet-trace|4fd02d7503e29c31ca7377d7c0507036377a32d2d0578e93d552ee807028be2e
"

while IFS='|' read -r name path want; do
  [ -z "$name" ] && continue
  echo "fetching $name ($VERSION)"
  curl -fsSL "$BASE/$path" -o "$OUT/$name"
  got=$(sha256sum "$OUT/$name" | cut -d' ' -f1)
  if [ "$got" != "$want" ]; then
    echo "checksum mismatch for $name" >&2
    echo "  want $want" >&2
    echo "  got  $got" >&2
    echo "the bytes behind a pinned url changed; review upstream and update VERSION and PINS in this file before publishing" >&2
    rm -f "$OUT/$name"
    exit 1
  fi
  chmod 0755 "$OUT/$name"
done <<< "$PINS"

printf '%s\n' "$VERSION" > "$OUT/dotnet-trace.version"

export DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
export DOTNET_CLI_TELEMETRY_OPTOUT=1
if ! "$OUT/dotnet-trace-linux-glibc-amd64" --version >/dev/null 2>&1; then
  echo "warning: version smoke failed on the runner; publishing the pinned $VERSION anyway" >&2
fi
cat "$OUT/dotnet-trace.version"
ls -la "$OUT"
