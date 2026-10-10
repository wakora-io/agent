#!/bin/sh
set -e
. /in/install-tools.sh
install_pinned composer "https://getcomposer.org/download/@VERSION@/composer.phar" /usr/local/bin/composer
install_pinned php-scoper "https://github.com/humbug/php-scoper/releases/download/@VERSION@/php-scoper.phar" /usr/local/bin/php-scoper
for TAR in /out/opentelemetry-php-sdk.tar.gz /out/opentelemetry-php-sdk81.tar.gz; do
  [ -f "$TAR" ] || continue
  rm -rf /work
  mkdir -p /work/src
  tar -C /work/src -xzf "$TAR"
  php-scoper add-prefix --working-dir /work/src --output-dir /work/scoped --config /in/scoper.inc.php --force --no-interaction --quiet
  COMPOSER_ALLOW_SUPERUSER=1 composer dump-autoload --working-dir /work/scoped --optimize --classmap-authoritative --quiet
  php -l /work/scoped/wakora-otel.php >/dev/null
  tar -C /work/scoped -czf "$TAR" composer.json composer.lock vendor wakora-otel.php
  echo "scoped: $(basename $TAR) ($(du -h $TAR | cut -f1))"
done
