<?php

if (PHP_VERSION_ID < 80200 || PHP_SAPI === 'cli' || !extension_loaded('opentelemetry')) {
    return;
}
if (getenv('OTEL_PHP_AUTOLOAD_ENABLED') !== false) {
    return;
}
$wakoraBase = ini_get('open_basedir');
if (is_string($wakoraBase) && $wakoraBase !== '') {
    $wakoraAllowed = false;
    foreach (explode(PATH_SEPARATOR, $wakoraBase) as $wakoraDir) {
        $wakoraDir = rtrim($wakoraDir, '/');
        if ($wakoraDir !== '' && strpos(__DIR__ . '/', $wakoraDir . '/') === 0) {
            $wakoraAllowed = true;
            break;
        }
    }
    if (!$wakoraAllowed) {
        return;
    }
}
try {
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
} catch (\Throwable $wakoraErr) {
    putenv('OTEL_PHP_AUTOLOAD_ENABLED');
    unset($_SERVER['OTEL_PHP_AUTOLOAD_ENABLED']);
    error_log('wakora-otel bootstrap disabled: ' . $wakoraErr->getMessage());
    return;
}
try {
    if (isset($_SERVER['REQUEST_METHOD']) && !isset($GLOBALS['wakoraRootSpan'])) {
        $wakoraScript = isset($_SERVER['SCRIPT_FILENAME']) ? (string) $_SERVER['SCRIPT_FILENAME'] : '';
        $wakoraScriptDir = $wakoraScript !== '' ? dirname($wakoraScript) : '';
        $wakoraIsWp = $wakoraScriptDir !== '' && (
            @file_exists($wakoraScriptDir . '/wp-settings.php')
            || @file_exists(dirname($wakoraScriptDir) . '/wp-settings.php')
        );
        if ($wakoraIsWp) {
            $wakoraDeepN = (int) $wakoraCfg('wakora.otel_deep_sample_n', '0');
            if ($wakoraDeepN > 0 && mt_rand(1, $wakoraDeepN) === 1) {
                $wakoraDeepPass = static function (): void {
                    static $wakoraTracer = null;
                    static $wakoraBudget = null;
                    static $wakoraWrapped = 0;
                    try {
                        if (!isset($GLOBALS['wp_filter']) || !class_exists('WP_Hook', false)) {
                            return;
                        }
                        if ($wakoraTracer === null) {
                            $wakoraTracer = \OpenTelemetry\API\Globals::tracerProvider()->getTracer('wakora.wp-deep');
                        }
                        if ($wakoraBudget === null) {
                            $wakoraBudget = new class {
                                public $spans = 2000;
                            };
                        }
                        $wakoraNameOf = static function ($cb): array {
                            try {
                                if (is_string($cb)) {
                                    $r = null;
                                    if (function_exists($cb)) {
                                        $r = new \ReflectionFunction($cb);
                                    }
                                    return [$cb, $r ? (string) $r->getFileName() : ''];
                                }
                                if (is_array($cb) && count($cb) === 2) {
                                    $cls = is_object($cb[0]) ? get_class($cb[0]) : (string) $cb[0];
                                    $m = new \ReflectionMethod($cb[0], $cb[1]);
                                    return [$cls . '::' . (string) $cb[1], (string) $m->getFileName()];
                                }
                                if ($cb instanceof \Closure) {
                                    $r = new \ReflectionFunction($cb);
                                    return ['{closure}', (string) $r->getFileName()];
                                }
                                if (is_object($cb)) {
                                    $m = new \ReflectionMethod($cb, '__invoke');
                                    return [get_class($cb) . '::__invoke', (string) $m->getFileName()];
                                }
                            } catch (\Throwable $e) {
                            }
                            return ['{unknown}', ''];
                        };
                        foreach ($GLOBALS['wp_filter'] as $wakoraTag => $wakoraHook) {
                            if ($wakoraWrapped >= 2000) {
                                break;
                            }
                            if ($wakoraTag === 'plugins_loaded' || !($wakoraHook instanceof \WP_Hook)) {
                                continue;
                            }
                            foreach ($wakoraHook->callbacks as $wakoraPrio => $wakoraCbs) {
                                foreach ($wakoraCbs as $wakoraIdx => $wakoraCb) {
                                    if ($wakoraWrapped >= 2000) {
                                        break 2;
                                    }
                                    $wakoraOrig = $wakoraCb['function'];
                                    if ($wakoraOrig instanceof \Closure) {
                                        $wakoraRef = new \ReflectionFunction($wakoraOrig);
                                        if (strpos((string) $wakoraRef->getFileName(), __DIR__) === 0) {
                                            continue;
                                        }
                                    }
                                    list($wakoraCbName, $wakoraCbFile) = $wakoraNameOf($wakoraOrig);
                                    $wakoraHook->callbacks[$wakoraPrio][$wakoraIdx]['function'] =
                                        static function (...$wakoraArgs) use ($wakoraOrig, $wakoraTag, $wakoraCbName, $wakoraCbFile, $wakoraTracer, $wakoraBudget) {
                                            if ($wakoraBudget->spans <= 0) {
                                                return $wakoraOrig(...$wakoraArgs);
                                            }
                                            $wakoraBudget->spans--;
                                            $wakoraSpan = $wakoraTracer->spanBuilder('hook:' . $wakoraTag)
                                                ->setAttribute('code.function', $wakoraCbName)
                                                ->setAttribute('code.filepath', $wakoraCbFile)
                                                ->startSpan();
                                            try {
                                                return $wakoraOrig(...$wakoraArgs);
                                            } finally {
                                                $wakoraSpan->end();
                                            }
                                        };
                                    $wakoraWrapped++;
                                }
                            }
                        }
                    } catch (\Throwable $wakoraDeepErr) {
                    }
                };
                $GLOBALS['wp_filter']['plugins_loaded'][PHP_INT_MAX][] = [
                    'function' => static function () use ($wakoraDeepPass): void {
                        $wakoraDeepPass();
                        try {
                            if (function_exists('add_action')) {
                                add_action('init', $wakoraDeepPass, PHP_INT_MAX);
                                add_action('wp', $wakoraDeepPass, PHP_INT_MAX);
                                add_action('template_redirect', $wakoraDeepPass, PHP_INT_MAX);
                            }
                        } catch (\Throwable $e) {
                        }
                    },
                    'accepted_args' => 0,
                ];
            }
        }
        if (!$wakoraIsWp) {
            register_shutdown_function(static function (): void {
                $wakoraPair = isset($GLOBALS['wakoraRootSpan']) ? $GLOBALS['wakoraRootSpan'] : null;
                unset($GLOBALS['wakoraRootSpan']);
                if (!is_array($wakoraPair)) {
                    return;
                }
                try {
                    $wakoraCode = http_response_code();
                    if (is_int($wakoraCode)) {
                        $wakoraPair[0]->setAttribute('http.response.status_code', $wakoraCode);
                        if ($wakoraCode >= 500) {
                            $wakoraPair[0]->setStatus(\OpenTelemetry\API\Trace\StatusCode::STATUS_ERROR);
                        }
                    }
                    $wakoraPair[1]->detach();
                    $wakoraPair[0]->end();
                } catch (\Throwable $wakoraEndErr) {
                }
            });
            $wakoraMethod = strtoupper((string) $_SERVER['REQUEST_METHOD']);
            $wakoraUri = isset($_SERVER['REQUEST_URI']) ? (string) $_SERVER['REQUEST_URI'] : '/';
            $wakoraPath = parse_url($wakoraUri, PHP_URL_PATH);
            if (!is_string($wakoraPath) || $wakoraPath === '') {
                $wakoraPath = '/';
            }
            $wakoraHost = isset($_SERVER['HTTP_HOST']) ? (string) $_SERVER['HTTP_HOST'] : (isset($_SERVER['SERVER_NAME']) ? (string) $_SERVER['SERVER_NAME'] : '');
            $wakoraScheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
            $wakoraSpan = \OpenTelemetry\API\Globals::tracerProvider()
                ->getTracer('wakora.request')
                ->spanBuilder($wakoraMethod . ' ' . $wakoraPath)
                ->setSpanKind(\OpenTelemetry\API\Trace\SpanKind::KIND_SERVER)
                ->setAttribute('http.request.method', $wakoraMethod)
                ->setAttribute('url.full', $wakoraScheme . '://' . $wakoraHost . $wakoraUri)
                ->setAttribute('url.path', $wakoraPath)
                ->setAttribute('url.scheme', $wakoraScheme)
                ->setAttribute('client.address', isset($_SERVER['REMOTE_ADDR']) ? (string) $_SERVER['REMOTE_ADDR'] : '')
                ->setAttribute('user_agent.original', isset($_SERVER['HTTP_USER_AGENT']) ? (string) $_SERVER['HTTP_USER_AGENT'] : '')
                ->startSpan();
            $GLOBALS['wakoraRootSpan'] = [$wakoraSpan, $wakoraSpan->activate()];
        }
    }
} catch (\Throwable $wakoraRootErr) {
}
