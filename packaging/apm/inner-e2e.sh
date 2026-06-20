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

mkdir -p /docroot-wp
touch /docroot-wp/wp-settings.php
cat > /docroot-wp/wp.php <<'EOF'
<?php
class WP_Hook
{
    public $callbacks = [];
}

$pre = isset($GLOBALS['wp_filter']) ? $GLOBALS['wp_filter'] : [];
$GLOBALS['wp_filter'] = [];
foreach ($pre as $tag => $prios) {
    $h = new WP_Hook();
    foreach ($prios as $p => $cbs) {
        foreach ($cbs as $i => $cb) {
            $h->callbacks[$p][$i] = $cb;
        }
    }
    $GLOBALS['wp_filter'][$tag] = $h;
}

function add_action($tag, $cb, $prio = 10)
{
    if (!isset($GLOBALS['wp_filter'][$tag])) {
        $GLOBALS['wp_filter'][$tag] = new WP_Hook();
    }
    $GLOBALS['wp_filter'][$tag]->callbacks[$prio][] = ['function' => $cb, 'accepted_args' => 1];
}

function do_hook($tag)
{
    if (!isset($GLOBALS['wp_filter'][$tag])) {
        return [];
    }
    $out = [];
    $cbs = $GLOBALS['wp_filter'][$tag]->callbacks;
    ksort($cbs);
    foreach ($cbs as $group) {
        foreach ($group as $cb) {
            $out[] = call_user_func($cb['function'], '');
        }
    }
    return $out;
}

function my_plugin_init()
{
    usleep(2000);
    add_action('late_hook', 'my_late_worker');
    return 'seen';
}

function my_late_worker()
{
    usleep(2000);
    return 'late';
}

$h = new WP_Hook();
$h->callbacks[10]['my_plugin_init'] = ['function' => 'my_plugin_init', 'accepted_args' => 1];
$GLOBALS['wp_filter']['init'] = $h;

$wrappedBefore = $GLOBALS['wp_filter']['init']->callbacks[10]['my_plugin_init']['function'];

if (isset($GLOBALS['wp_filter']['plugins_loaded'])) {
    foreach ($GLOBALS['wp_filter']['plugins_loaded']->callbacks as $cbs) {
        foreach ($cbs as $cb) {
            call_user_func($cb['function']);
        }
    }
}

$wrappedAfter = $GLOBALS['wp_filter']['init']->callbacks[10]['my_plugin_init']['function'];
$out = do_hook('init');
$late = 'missing';
if (isset($GLOBALS['wp_filter']['late_hook'])) {
    foreach ($GLOBALS['wp_filter']['late_hook']->callbacks as $group) {
        foreach ($group as $cb) {
            $late = is_string($cb['function']) ? 'plain' : 'wrapped';
        }
    }
}
$out = array_filter($out, function ($v) { return $v !== null && $v !== ''; });
echo 'wp-' . implode(',', $out) . ($wrappedAfter !== $wrappedBefore ? '-wrapped' : '-plain') . '-late.' . $late;
EOF

php -d "extension=/art/$SO" \
    -d "auto_prepend_file=/sdk/wakora-otel.php" \
    -d "wakora.otel_service=e2e-php-wp-deep" \
    -d "wakora.otel_endpoint=http://127.0.0.1:4319" \
    -d "wakora.otel_deep_sample_n=1" \
    -S 127.0.0.1:8085 -t /docroot-wp >/dev/null 2>&1 &
sleep 2
body=$(php -r 'echo file_get_contents("http://127.0.0.1:8085/wp.php");')
[ "$body" = "wp-seen-wrapped-late.wrapped" ] || { echo "deep-trace wrap chain broken (want wrapped + late-pass wrapped): $body"; exit 1; }
sleep 3
grep -q 'hook:init' /tmp/otlp-body.bin || { echo "hook span missing from the export"; exit 1; }
grep -q 'my_plugin_init' /tmp/otlp-body.bin || { echo "callback identity missing from the hook span"; exit 1; }
echo "e2e ok: sampled wp deep-trace wraps boot and runtime-registered callbacks"

php -d "extension=/art/$SO" \
    -d "auto_prepend_file=/sdk/wakora-otel.php" \
    -d "wakora.otel_service=e2e-php-wp-off" \
    -d "wakora.otel_endpoint=http://127.0.0.1:4318" \
    -S 127.0.0.1:8086 -t /docroot-wp >/dev/null 2>&1 &
sleep 2
body=$(php -r 'echo file_get_contents("http://127.0.0.1:8086/wp.php");')
[ "$body" = "wp-seen-plain-late.plain" ] || { echo "deep-trace must stay off without the ini key: $body"; exit 1; }
echo "e2e ok: deep-trace stays fully inert without wakora.otel_deep_sample_n"

cat > /docroot/page.php <<'EOF'
<?php
echo '<html><head><title>t</title></head><body>hello</body></html>';
EOF
cat > /docroot/feed.php <<'EOF'
<?php
header('Content-Type: application/json');
echo '{"a":"<html><head></head></html>"}';
EOF
body=$(php -r '$c=stream_context_create(["http"=>["header"=>"Accept: text/html"]]);echo file_get_contents("http://127.0.0.1:8080/page.php",false,$c);')
case "$body" in
  *data-wakora-rum*) echo "rum snippet must NOT inject without rum-sites.php"; exit 1;;
esac
body=$(php -r '$c=stream_context_create(["http"=>["method"=>"POST","content"=>"{}","ignore_errors"=>true]]);echo file_get_contents("http://127.0.0.1:8080/page.php?wkr-rum=1",false,$c);')
case "$body" in
  *hello*) : ;;
  *) echo "beacon marker must fall through to the app without rum-sites.php (got $body)"; exit 1;;
esac
echo "e2e ok: rum stays fully inert without rum-sites.php"

echo "<?php return ['127.0.0.1'=>1];" > /rum-sites.php
body=$(php -r '$c=stream_context_create(["http"=>["header"=>"Accept: text/html"]]);echo file_get_contents("http://127.0.0.1:8080/page.php",false,$c);')
case "$body" in
  *data-wakora-rum*) : ;;
  *) echo "rum snippet missing on an enabled site"; exit 1;;
esac
case "$body" in
  *"</head>"*) : ;;
  *) echo "injection destroyed the head tag"; exit 1;;
esac
echo "e2e ok: rum snippet injects before </head> on the enabled site"

body=$(php -r '$c=stream_context_create(["http"=>["header"=>"Sec-Fetch-Dest: style"]]);echo file_get_contents("http://127.0.0.1:8080/page.php",false,$c);')
case "$body" in
  *data-wakora-rum*) echo "rum must not wrap non-document requests (css/js served via php would 500)"; exit 1;;
esac
echo "e2e ok: a non-document request is not wrapped by the rum ob_start"

body=$(php -r '$c=stream_context_create(["http"=>["header"=>"Accept: text/html"]]);echo file_get_contents("http://127.0.0.1:8080/feed.php",false,$c);')
case "$body" in
  *data-wakora-rum*) echo "rum snippet must not inject into non-html responses"; exit 1;;
esac
echo "e2e ok: non-html responses stay untouched"

lines_before=$(grep -c 'POST /v1/rum' /tmp/otlp.log || true)
code=$(php -r '$c=stream_context_create(["http"=>["method"=>"POST","header"=>"Content-Type: application/json","content"=>"{\"site\":\"127.0.0.1\",\"path\":\"/checkout\",\"vitals\":{\"lcp\":1200,\"cls\":0.03},\"errors\":[{\"msg\":\"boom\",\"n\":2}]}","ignore_errors"=>true]]);@file_get_contents("http://127.0.0.1:8080/page.php?wkr-rum=1",false,$c);preg_match("#\\s(\\d{3})\\s#",$http_response_header[0],$m);echo $m[1];')
[ "$code" = "204" ] || { echo "beacon on the enabled site must answer 204 (got $code)"; exit 1; }
sleep 1
lines_after=$(grep -c 'POST /v1/rum' /tmp/otlp.log || true)
[ "$lines_after" -gt "$lines_before" ] || { echo "beacon was not relayed to the agent endpoint"; exit 1; }
echo "e2e ok: beacon answers 204 and relays to the agent"

echo "<?php return ['other.example.com'=>1];" > /rum-sites.php
body=$(php -r '$c=stream_context_create(["http"=>["header"=>"Accept: text/html"]]);echo file_get_contents("http://127.0.0.1:8080/page.php",false,$c);')
case "$body" in
  *data-wakora-rum*) echo "rum snippet must not inject on a not-enabled site"; exit 1;;
esac
body=$(php -r '$c=stream_context_create(["http"=>["method"=>"POST","content"=>"{}","ignore_errors"=>true]]);echo file_get_contents("http://127.0.0.1:8080/page.php?wkr-rum=1",false,$c);')
case "$body" in
  *hello*) : ;;
  *) echo "beacon on a not-enabled site must fall through to the app (got $body)"; exit 1;;
esac
rm -f /rum-sites.php
echo "e2e ok: a not-enabled site neither injects nor accepts beacons"

echo "<?php return ['127.0.0.1'=>1];" > /rum-sites.php
cat > /docroot/hosted.php <<'EOF'
<?php
echo '<html><head><title>t</title><script async src="https://rum.wakora.io/w.js" data-site="example.com"></script></head><body>hosted</body></html>';
EOF
body=$(php -r '$c=stream_context_create(["http"=>["header"=>"Accept: text/html"]]);echo file_get_contents("http://127.0.0.1:8080/hosted.php",false,$c);')
case "$body" in
  *data-wakora-rum*) echo "prepend must yield to a hosted w.js snippet already on the page (double beacons bill twice)"; exit 1;;
esac
rm -f /rum-sites.php
echo "e2e ok: a page carrying the hosted snippet stays untouched - no double collection"
