#!/bin/sh
set -e
VARIANT="${1:-}"
OUTNAME="opentelemetry-php-sdk$VARIANT"
MINID=80200
PKGS="open-telemetry/opentelemetry-auto-pdo open-telemetry/opentelemetry-auto-mysqli open-telemetry/opentelemetry-auto-curl"
if [ "$VARIANT" = "81" ]; then
  MINID=80100
  PKGS=""
fi
export DEBIAN_FRONTEND=noninteractive
apt-get update -q >/dev/null
apt-get install -y -q git unzip >/dev/null
php -r "copy('https://getcomposer.org/installer', '/tmp/composer-setup.php');"
php /tmp/composer-setup.php --install-dir=/usr/local/bin --filename=composer --quiet
mkdir /build
cd /build
composer init --no-interaction --name wakora/otel-php-sdk --description "Wakora vendored OTel PHP SDK bundle" >/dev/null 2>&1
composer config platform-check false
COMPOSER_ALLOW_SUPERUSER=1 composer require --no-interaction \
  --ignore-platform-req=ext-opentelemetry \
  --ignore-platform-req=ext-mysqli \
  open-telemetry/sdk \
  open-telemetry/exporter-otlp \
  guzzlehttp/guzzle \
  open-telemetry/opentelemetry-auto-wordpress \
  $PKGS
sed "s/PHP_VERSION_ID < 80200/PHP_VERSION_ID < $MINID/" /in/wakora-otel.php > /build/wakora-otel.php
php -l /build/wakora-otel.php >/dev/null
tar -C /build -czf "/out/$OUTNAME.tar.gz" composer.json composer.lock vendor wakora-otel.php
echo "sdk bundle packed: $OUTNAME.tar.gz ($(du -h /out/$OUTNAME.tar.gz | cut -f1))"
