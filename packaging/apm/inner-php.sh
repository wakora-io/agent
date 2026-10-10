#!/bin/sh
set -e
EXTVER="$1"
NAME="$2"
WANT="$(awk -v v="$EXTVER" '$1 == "php-ext" && $2 == v {print $3}' /in/tools.lock)"
if [ -z "$WANT" ]; then
  echo "no pinned sha256 for extension source $EXTVER in tools.lock" >&2
  exit 1
fi
if command -v apk >/dev/null 2>&1; then
  apk add --no-cache $PHPIZE_DEPS curl binutils >/dev/null
else
  apt-get update -q >/dev/null
  apt-get install -y -q $PHPIZE_DEPS curl binutils >/dev/null
fi
cd /tmp
curl -fsSL "https://github.com/open-telemetry/opentelemetry-php-instrumentation/archive/refs/tags/$EXTVER.tar.gz" -o ext.tar.gz
echo "$WANT  ext.tar.gz" | sha256sum -c - >/dev/null
tar xzf ext.tar.gz
cd "opentelemetry-php-instrumentation-$EXTVER/ext"
phpize >/dev/null
./configure >/dev/null
make -j"$(nproc)" >/dev/null
strip modules/opentelemetry.so
php -d "extension=$PWD/modules/opentelemetry.so" -m | grep -qi '^opentelemetry$'
cp modules/opentelemetry.so "/out/$NAME"
