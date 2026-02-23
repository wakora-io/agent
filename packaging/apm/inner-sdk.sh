#!/bin/sh
set -e
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
  open-telemetry/opentelemetry-auto-pdo \
  open-telemetry/opentelemetry-auto-mysqli \
  open-telemetry/opentelemetry-auto-curl
cp /in/wakora-otel.php /build/
php -l /build/wakora-otel.php >/dev/null
tar -C /build -czf /out/opentelemetry-php-sdk.tar.gz composer.json composer.lock vendor wakora-otel.php
echo "sdk bundle packed ($(du -h /out/opentelemetry-php-sdk.tar.gz | cut -f1))"
