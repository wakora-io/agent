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

cat > /recv/dumpbody.php <<'EOF'
<?php
file_put_contents('/tmp/otlp-body.bin', file_get_contents('php://input'), FILE_APPEND);
echo '{}';
EOF
php -S 127.0.0.1:4319 /recv/dumpbody.php >/dev/null 2>&1 &
php -d "extension=/art/$SO" \
    -d "auto_prepend_file=/sdk/wakora-otel.php" \
    -d "wakora.otel_service=e2e-php-root" \
    -d "wakora.otel_endpoint=http://127.0.0.1:4319" \
    -S 127.0.0.1:8083 -t /docroot >/dev/null 2>&1 &
sleep 2
body=$(php -r 'echo file_get_contents("http://127.0.0.1:8083/x.php");')
[ "$body" = "ok" ] || { echo "root-span app request failed: $body"; exit 1; }
sleep 3
# the generic request root is a SERVER span named "GET /x.php" - a non-WP app
# must not export client-only traces (protobuf body carries the span name raw)
grep -q 'GET /x.php' /tmp/otlp-body.bin || { echo "generic root span missing from the export"; exit 1; }
echo "e2e ok: non-WP request exports a generic server root span"

mkdir -p /docroot/psr1
cat > /docroot/psr1/UriInterface.php <<'EOF'
<?php
namespace Psr\Http\Message;

interface UriInterface
{
    public function getScheme();
    public function getAuthority();
    public function getUserInfo();
    public function getHost();
    public function getPort();
    public function getPath();
    public function getQuery();
    public function getFragment();
    public function withScheme($scheme);
    public function withUserInfo($user, $password = null);
    public function withHost($host);
    public function withPort($port);
    public function withPath($path);
    public function withQuery($query);
    public function withFragment($fragment);
    public function __toString();
}
EOF
cat > /docroot/legacy.php <<'EOF'
<?php
require __DIR__ . '/psr1/UriInterface.php';

class LegacyUri implements \Psr\Http\Message\UriInterface
{
    public function getScheme() { return 'http'; }
    public function getAuthority() { return ''; }
    public function getUserInfo() { return ''; }
    public function getHost() { return 'localhost'; }
    public function getPort() { return null; }
    public function getPath() { return '/'; }
    public function getQuery() { return ''; }
    public function getFragment() { return ''; }
    public function withScheme($scheme) { return $this; }
    public function withUserInfo($user, $password = null) { return $this; }
    public function withHost($host) { return $this; }
    public function withPort($port) { return $this; }
    public function withPath($path) { return $this; }
    public function withQuery($query) { return $this; }
    public function withFragment($fragment) { return $this; }
    public function __toString() { return 'http://localhost/'; }
}

$u = new LegacyUri();
echo 'legacy-' . $u->getScheme();
EOF
php -d "extension=/art/$SO" \
    -d "auto_prepend_file=/sdk/wakora-otel.php" \
    -d "wakora.otel_service=e2e-php-legacy-psr" \
    -d "wakora.otel_endpoint=http://127.0.0.1:4318" \
    -S 127.0.0.1:8084 -t /docroot >/dev/null 2>&1 &
sleep 2
lines_before=$(grep -c 'POST /v1/traces' /tmp/otlp.log)
body=$(php -r 'echo file_get_contents("http://127.0.0.1:8084/legacy.php");')
[ "$body" = "legacy-http" ] || { echo "untyped psr-7 app broke under the prepend: $body"; exit 1; }
sleep 3
lines_after=$(grep -c 'POST /v1/traces' /tmp/otlp.log)
[ "$lines_after" -gt "$lines_before" ] || { echo "untyped psr-7 app must still export spans"; exit 1; }
echo "e2e ok: app-vendored untyped psr-7 coexists with the scoped sdk"

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
