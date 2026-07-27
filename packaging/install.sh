#!/bin/sh
set -eu

BASE="https://get.wakora.io"
PUBKEY="__WAKORA_PUBKEY__"
PUBKEY_EC="__WAKORA_PUBKEY_EC__"
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
  export KEY
  exec sudo -E sh -c 'curl -fsSL '"$BASE"'/install.sh | sh -s -- ${KEY:+--key "$KEY"}'
fi

OS="$(uname -s)"
ARCH="$(uname -m)"
case "$OS" in
  Linux)
    case "$ARCH" in
      x86_64|amd64) ASSET="wakora" ;;
      aarch64|arm64) ASSET="wakora-linux-arm64" ;;
      *) echo "unsupported linux arch: $ARCH (amd64/arm64 published)" >&2; exit 1 ;;
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

if [ -z "$PUBKEY" ] || [ "$PUBKEY" = "__WAKORA_PUBKEY__" ]; then
  echo "installer has no publisher key baked in; refusing to install an unverified binary" >&2
  echo "(the get.wakora.io deploy must replace __WAKORA_PUBKEY__ with the real key)" >&2
  rm -f "$TMP"; exit 1
fi
if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl required to verify the signed binary but not found; aborting" >&2
  rm -f "$TMP"; exit 1
fi
# ed25519 needs pkeyutl -rawin (openssl >= 3); older systems (Ubuntu 20.04,
# Debian 10: openssl 1.1.1) verify the ECDSA co-signature instead - same
# binary, second key, still fail-closed everywhere
if openssl pkeyutl -help 2>&1 | grep -q rawin; then
  if ! curl -fsSL "$BASE/bin/$ASSET.sig" -o "$TMP.sig" 2>/dev/null || [ ! -s "$TMP.sig" ]; then
    echo "binary signature missing from channel; aborting" >&2
    rm -f "$TMP" "$TMP.sig"; exit 1
  fi
  printf -- '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA%s\n-----END PUBLIC KEY-----\n' "$PUBKEY" > "$TMP.pem"
  openssl base64 -d -A -in "$TMP.sig" -out "$TMP.sigbin" 2>/dev/null || true
  if openssl pkeyutl -verify -pubin -inkey "$TMP.pem" -rawin -in "$TMP" -sigfile "$TMP.sigbin" >/dev/null 2>&1; then
    echo "signature verified"
  else
    echo "binary signature INVALID; aborting" >&2
    rm -f "$TMP" "$TMP.sig" "$TMP.pem" "$TMP.sigbin"; exit 1
  fi
  rm -f "$TMP.sig" "$TMP.pem" "$TMP.sigbin"
else
  if [ -z "$PUBKEY_EC" ] || [ "$PUBKEY_EC" = "__WAKORA_PUBKEY_EC__" ]; then
    echo "this openssl cannot verify ed25519 and the installer has no EC key baked in; aborting" >&2
    echo "(the get.wakora.io deploy must replace __WAKORA_PUBKEY_EC__ with the real key)" >&2
    rm -f "$TMP"; exit 1
  fi
  if ! curl -fsSL "$BASE/bin/$ASSET.sig2" -o "$TMP.sig2" 2>/dev/null || [ ! -s "$TMP.sig2" ]; then
    echo "legacy co-signature missing from channel; aborting" >&2
    rm -f "$TMP" "$TMP.sig2"; exit 1
  fi
  printf -- '-----BEGIN PUBLIC KEY-----\n' > "$TMP.pem"
  printf '%s\n' "$PUBKEY_EC" | fold -w 64 >> "$TMP.pem"
  printf -- '-----END PUBLIC KEY-----\n' >> "$TMP.pem"
  if openssl dgst -sha256 -verify "$TMP.pem" -signature "$TMP.sig2" "$TMP" >/dev/null 2>&1; then
    echo "signature verified (ecdsa co-signature - this openssl is too old for ed25519)"
  else
    echo "binary signature INVALID; aborting" >&2
    rm -f "$TMP" "$TMP.sig2" "$TMP.pem"; exit 1
  fi
  rm -f "$TMP.sig2" "$TMP.pem"
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
  mkdir -p /var/log/wakora /var/lib/wakora
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
StateDirectory=wakora
Nice=10
CPUQuota=30%
OOMScoreAdjust=500
IOSchedulingClass=best-effort
IOSchedulingPriority=7
ProtectHome=read-only
ProtectSystem=strict
ReadWritePaths=/etc/wakora /var/lib/wakora /var/log/wakora /usr/local/bin
ProtectControlGroups=yes

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now wakora-agent
else
  echo "no systemd/launchd; run /usr/local/bin/wakora under your init (openrc/sysvinit templates in agent/packaging/)" >&2
fi

echo "Done! Host will appear in the console within ~1 minute"

# self-diagnostics: a green checklist beats silence as a first impression. this
# is display-only - a transient "data flow: connecting" right after install must
# never fail the installer, so the doctor's exit code is ignored
sleep 2
echo
/usr/local/bin/wakora doctor || true
