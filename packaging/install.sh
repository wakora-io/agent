#!/bin/sh
set -eu

BASE="https://get.wakora.io"
KEY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --key) KEY="${2:-}"; shift 2 ;;
    --key=*) KEY="${1#--key=}"; shift ;;
    *) shift ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "wakora installer needs root; re-running with sudo" >&2
  exec sudo -E sh -c "$(cat)" -- ${KEY:+--key "$KEY"}
fi

OS="$(uname -s)"
ARCH="$(uname -m)"
case "$OS" in
  Linux)
    case "$ARCH" in
      x86_64|amd64) ASSET="wakora" ;;
      *) echo "unsupported linux arch: $ARCH (only amd64 published)" >&2; exit 1 ;;
    esac
    SHACMD="sha256sum" ;;
  Darwin)
    case "$ARCH" in
      x86_64) ASSET="wakora-darwin-amd64" ;;
      arm64)  ASSET="wakora-darwin-arm64" ;;
      *) echo "unsupported macos arch: $ARCH" >&2; exit 1 ;;
    esac
    SHACMD="shasum -a 256" ;;
  *) echo "unsupported OS: $OS" >&2; exit 1 ;;
esac

TMP="$(mktemp)"
echo "downloading $ASSET ..."
curl -fsSL "$BASE/bin/$ASSET" -o "$TMP"
WANT="$(curl -fsSL "$BASE/bin/$ASSET.sha256" | tr -d '[:space:]')"
GOT="$($SHACMD "$TMP" | cut -d' ' -f1)"
if [ "$WANT" != "$GOT" ]; then
  echo "checksum mismatch (want $WANT got $GOT)" >&2
  rm -f "$TMP"; exit 1
fi

install -m 0755 "$TMP" /usr/local/bin/wakora
rm -f "$TMP"
echo "installed /usr/local/bin/wakora ($(/usr/local/bin/wakora --version))"

if [ -n "$KEY" ]; then
  /usr/local/bin/wakora --key "$KEY"
else
  echo "no --key given; register later with: sudo wakora --key <TEAMKEY>" >&2
fi

if [ "$OS" = "Darwin" ]; then
  /usr/local/bin/wakora service install
elif command -v systemctl >/dev/null 2>&1; then
  mkdir -p /var/log/wakora
  cat > /etc/systemd/system/wakora-agent.service <<'UNIT'
[Unit]
Description=Wakora Agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/wakora
Restart=always
RestartSec=3
User=root
Nice=10
CPUQuota=30%
MemoryHigh=160M
MemoryMax=256M
OOMScoreAdjust=500
IOSchedulingClass=best-effort
IOSchedulingPriority=7
ProtectHome=read-only

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now wakora-agent
else
  echo "no systemd/launchd; run /usr/local/bin/wakora under your init (openrc/sysvinit templates in agent/packaging/)" >&2
fi

echo "done - host will appear in the console within ~1 min"
