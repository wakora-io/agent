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
$wakoraEnv = static function (string $key, string $value): void {
    putenv($key . '=' . $value);
    $_SERVER[$key] = $value;
};
$wakoraEnv('OTEL_PHP_AUTOLOAD_ENABLED', 'true');
$wakoraEnv('OTEL_RESOURCE_ATTRIBUTES', 'php.version=' . PHP_VERSION . ',php.sapi=' . PHP_SAPI);
$wakoraEnv('OTEL_SERVICE_NAME', $wakoraCfg('wakora.otel_service', 'php-app'));
$wakoraEnv('OTEL_EXPORTER_OTLP_ENDPOINT', $wakoraCfg('wakora.otel_endpoint', 'http://127.0.0.1:4318'));
$wakoraEnv('OTEL_EXPORTER_OTLP_PROTOCOL', 'http/protobuf');
$wakoraEnv('OTEL_TRACES_EXPORTER', 'otlp');
$wakoraEnv('OTEL_METRICS_EXPORTER', 'none');
$wakoraEnv('OTEL_LOGS_EXPORTER', 'none');
$wakoraEnv('OTEL_PROPAGATORS', 'tracecontext,baggage');
require __DIR__ . '/vendor/autoload.php';
