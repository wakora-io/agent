#!/bin/sh
set -e
php -r "copy('https://getcomposer.org/installer', '/tmp/composer-setup.php');"
php /tmp/composer-setup.php --install-dir=/usr/local/bin --filename=composer --quiet
php -r "copy('https://github.com/humbug/php-scoper/releases/latest/download/php-scoper.phar', '/usr/local/bin/php-scoper');"
chmod +x /usr/local/bin/php-scoper
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
