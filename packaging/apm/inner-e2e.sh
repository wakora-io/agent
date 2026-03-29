#!/bin/sh
set -e
SO="$1"
mkdir /sdk /docroot /recv
tar -C /sdk -xzf /art/opentelemetry-php-sdk.tar.gz

cat > /recv/dump.php <<'EOF'
<?php
$len = strlen(file_get_contents('php://input'));
file_put_contents('/tmp/otlp.log', $_SERVER['REQUEST_METHOD'] . ' ' . $_SERVER['REQUEST_URI'] . " len=$len\n", FILE_APPEND);
echo '{}';
EOF

cat > /docroot/x.php <<'EOF'
<?php
$ch = curl_init('http://127.0.0.1:4318/ping');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_exec($ch);
curl_close($ch);
echo 'ok';
EOF

php -S 127.0.0.1:4318 /recv/dump.php >/dev/null 2>&1 &
php -d "extension=/art/$SO" \
    -d "auto_prepend_file=/sdk/wakora-otel.php" \
    -d "wakora.otel_service=e2e-php" \
    -d "wakora.otel_endpoint=http://127.0.0.1:4318" \
    -S 127.0.0.1:8080 -t /docroot >/dev/null 2>&1 &
sleep 2
body=$(php -r 'echo file_get_contents("http://127.0.0.1:8080/x.php");')
[ "$body" = "ok" ] || { echo "app request failed: $body"; exit 1; }
sleep 3
grep 'POST /v1/traces' /tmp/otlp.log || { echo "no OTLP export seen"; cat /tmp/otlp.log 2>/dev/null; exit 1; }
echo "e2e ok: spans exported over OTLP"

php -d "extension=/art/$SO" \
    -d "auto_prepend_file=/sdk/wakora-otel.php" \
    -d "open_basedir=/docroot:/tmp:/sdk" \
    -d "wakora.otel_service=e2e-php-basedir-allowed" \
    -d "wakora.otel_endpoint=http://127.0.0.1:4318" \
    -S 127.0.0.1:8081 -t /docroot >/dev/null 2>&1 &
sleep 2
lines_before=$(grep -c 'POST /v1/traces' /tmp/otlp.log)
body=$(php -r 'echo file_get_contents("http://127.0.0.1:8081/x.php");')
[ "$body" = "ok" ] || { echo "open_basedir-allowed pool failed: $body"; exit 1; }
sleep 3
lines_after=$(grep -c 'POST /v1/traces' /tmp/otlp.log)
[ "$lines_after" -gt "$lines_before" ] || { echo "open_basedir-allowed pool must still export spans"; exit 1; }
echo "e2e ok: open_basedir pool with sdk dir allowed exports spans"

php -d "extension=/art/$SO" \
    -d "auto_prepend_file=/sdk/wakora-otel.php" \
    -d "open_basedir=/docroot:/tmp:/sdk/wakora-otel.php" \
    -d "wakora.otel_service=e2e-php-guarded" \
    -d "wakora.otel_endpoint=http://127.0.0.1:4318" \
    -S 127.0.0.1:8082 -t /docroot >/dev/null 2>&1 &
sleep 2
lines_before=$(grep -c 'POST /v1/traces' /tmp/otlp.log)
body=$(php -r 'echo file_get_contents("http://127.0.0.1:8082/x.php");')
[ "$body" = "ok" ] || { echo "guarded pool failed (bootstrap must skip, not fatal): $body"; exit 1; }
sleep 2
lines_after=$(grep -c 'POST /v1/traces' /tmp/otlp.log)
[ "$lines_after" = "$lines_before" ] || { echo "guarded pool must not export spans"; exit 1; }
echo "e2e ok: vendor outside open_basedir skips bootstrap without breaking the site"
