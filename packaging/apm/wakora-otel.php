<?php

if (PHP_VERSION_ID < 80200 || PHP_SAPI === 'cli' || !extension_loaded('opentelemetry')) {
    return;
}
if (getenv('OTEL_PHP_AUTOLOAD_ENABLED') !== false) {
    return;
}
$wakoraCfg = static function (string $key, string $fallback): string {
    $v = get_cfg_var($key);
    return is_string($v) && $v !== '' ? $v : $fallback;
};
putenv('OTEL_PHP_AUTOLOAD_ENABLED=true');
putenv('OTEL_SERVICE_NAME=' . $wakoraCfg('wakora.otel_service', 'php-app'));
putenv('OTEL_EXPORTER_OTLP_ENDPOINT=' . $wakoraCfg('wakora.otel_endpoint', 'http://127.0.0.1:4318'));
putenv('OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf');
putenv('OTEL_TRACES_EXPORTER=otlp');
putenv('OTEL_METRICS_EXPORTER=none');
putenv('OTEL_LOGS_EXPORTER=none');
putenv('OTEL_PROPAGATORS=tracecontext,baggage');
require __DIR__ . '/vendor/autoload.php';
