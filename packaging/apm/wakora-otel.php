<?php

if (PHP_SAPI !== 'cli'
    && isset($_SERVER['REQUEST_METHOD'], $_SERVER['HTTP_HOST'], $_GET['wkr-rum'])
    && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $wakoraRumOwn = false;
    $wakoraRumSites = @include dirname(__DIR__) . '/rum-sites.php';
    if (is_array($wakoraRumSites) && count($wakoraRumSites)) {
        $wakoraRumSite = strtolower((string) $_SERVER['HTTP_HOST']);
        $wakoraRumP = strpos($wakoraRumSite, ':');
        if ($wakoraRumP !== false) {
            $wakoraRumSite = substr($wakoraRumSite, 0, $wakoraRumP);
        }
        if (strncmp($wakoraRumSite, 'www.', 4) === 0) {
            $wakoraRumSite = substr($wakoraRumSite, 4);
        }
        if (isset($wakoraRumSites[$wakoraRumSite])) {
            $wakoraRumOwn = true;
            try {
                $wakoraRumRaw = file_get_contents('php://input', false, null, 0, 32768);
                $wakoraRumB = is_string($wakoraRumRaw) && $wakoraRumRaw !== '' ? json_decode($wakoraRumRaw, true, 4) : null;
                if (is_array($wakoraRumB)) {
                    $wakoraRumVitals = [];
                    if (isset($wakoraRumB['vitals']) && is_array($wakoraRumB['vitals'])) {
                        foreach ($wakoraRumB['vitals'] as $wakoraRumK => $wakoraRumV) {
                            if (is_string($wakoraRumK) && is_numeric($wakoraRumV)) {
                                $wakoraRumVitals[substr($wakoraRumK, 0, 8)] = (float) $wakoraRumV;
                            }
                        }
                    }
                    $wakoraRumErrs = [];
                    if (isset($wakoraRumB['errors']) && is_array($wakoraRumB['errors'])) {
                        foreach (array_slice($wakoraRumB['errors'], 0, 10) as $wakoraRumE) {
                            if (is_array($wakoraRumE) && isset($wakoraRumE['msg']) && is_string($wakoraRumE['msg'])) {
                                $wakoraRumErrs[] = [
                                    'msg' => substr($wakoraRumE['msg'], 0, 250),
                                    'src' => isset($wakoraRumE['src']) && is_string($wakoraRumE['src']) ? substr($wakoraRumE['src'], 0, 120) : '',
                                    'n' => isset($wakoraRumE['n']) && is_numeric($wakoraRumE['n']) ? max(1, (int) $wakoraRumE['n']) : 1,
                                ];
                            }
                        }
                    }
                    $wakoraRumFrust = [];
                    if (isset($wakoraRumB['frust']) && is_array($wakoraRumB['frust'])) {
                        foreach (array_slice($wakoraRumB['frust'], 0, 5) as $wakoraRumF) {
                            if (is_array($wakoraRumF) && isset($wakoraRumF['name']) && is_string($wakoraRumF['name'])
                                && ($wakoraRumF['name'] === 'rage' || $wakoraRumF['name'] === 'error_click')) {
                                $wakoraRumFrust[] = [
                                    'name' => $wakoraRumF['name'],
                                    'sel' => isset($wakoraRumF['sel']) && is_string($wakoraRumF['sel']) ? substr($wakoraRumF['sel'], 0, 120) : '',
                                    'count' => isset($wakoraRumF['count']) && is_numeric($wakoraRumF['count']) ? max(1, min(1000, (int) $wakoraRumF['count'])) : 1,
                                ];
                            }
                        }
                    }
                    $wakoraRumCrumbs = '';
                    if (isset($wakoraRumB['crumbs']) && is_string($wakoraRumB['crumbs'])
                        && $wakoraRumB['crumbs'] !== '' && strlen($wakoraRumB['crumbs']) <= 2048
                        && is_array(json_decode($wakoraRumB['crumbs'], true, 4))) {
                        $wakoraRumCrumbs = $wakoraRumB['crumbs'];
                    }
                    $wakoraRumIp = '';
                    foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'] as $wakoraRumIpK) {
                        if (isset($_SERVER[$wakoraRumIpK]) && is_string($_SERVER[$wakoraRumIpK]) && $_SERVER[$wakoraRumIpK] !== '') {
                            $wakoraRumIp = trim(strtok((string) $_SERVER[$wakoraRumIpK], ','));
                            break;
                        }
                    }
                    if ($wakoraRumIp !== '' && filter_var($wakoraRumIp, FILTER_VALIDATE_IP) === false) {
                        $wakoraRumIp = '';
                    }
                    $wakoraRumOut = json_encode([
                        'site' => $wakoraRumSite,
                        'path' => isset($wakoraRumB['path']) && is_string($wakoraRumB['path']) ? substr($wakoraRumB['path'], 0, 300) : '/',
                        'dev' => isset($wakoraRumB['dev']) && is_string($wakoraRumB['dev']) ? substr($wakoraRumB['dev'], 0, 30) : '',
                        'browser' => isset($wakoraRumB['browser']) && is_string($wakoraRumB['browser']) ? substr($wakoraRumB['browser'], 0, 30) : '',
                        'ip' => $wakoraRumIp,
                        'trace' => isset($wakoraRumB['trace']) && is_string($wakoraRumB['trace']) && preg_match('/^[0-9a-f]{32}$/', $wakoraRumB['trace']) ? $wakoraRumB['trace'] : '',
                        'vitals' => $wakoraRumVitals,
                        'errors' => $wakoraRumErrs,
                        'frust' => $wakoraRumFrust,
                        'crumbs' => $wakoraRumCrumbs,
                    ]);
                    $wakoraRumCfg = get_cfg_var('wakora.otel_endpoint');
                    $wakoraRumEp = (is_string($wakoraRumCfg) && $wakoraRumCfg !== '' ? $wakoraRumCfg : 'http://127.0.0.1:4318') . '/v1/rum';
                    if (function_exists('curl_init')) {
                        $wakoraRumCh = curl_init($wakoraRumEp);
                        curl_setopt_array($wakoraRumCh, [
                            CURLOPT_POST => true,
                            CURLOPT_POSTFIELDS => $wakoraRumOut,
                            CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
                            CURLOPT_RETURNTRANSFER => true,
                            CURLOPT_CONNECTTIMEOUT_MS => 150,
                            CURLOPT_TIMEOUT_MS => 400,
                        ]);
                        curl_exec($wakoraRumCh);
                        curl_close($wakoraRumCh);
                    } else {
                        @file_get_contents($wakoraRumEp, false, stream_context_create(['http' => [
                            'method' => 'POST',
                            'header' => 'Content-Type: application/json',
                            'content' => $wakoraRumOut,
                            'timeout' => 0.5,
                        ]]));
                    }
                }
            } catch (\Throwable $wakoraRumErr) {
            }
        }
    }
    if ($wakoraRumOwn) {
        while (ob_get_level() > 0) {
            @ob_end_clean();
        }
        http_response_code(204);
        header('Cache-Control: no-store');
        exit;
    }
    unset($wakoraRumOwn, $wakoraRumSites, $wakoraRumSite, $wakoraRumP);
}

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
$wakoraStSend = static function (): void {
    static $wakoraStDone = false;
    if ($wakoraStDone || headers_sent()) {
        return;
    }
    try {
        $wakoraStCtx = \OpenTelemetry\API\Trace\Span::getCurrent()->getContext();
        if ($wakoraStCtx->isValid()) {
            header('Server-Timing: traceparent;desc="00-' . $wakoraStCtx->getTraceId() . '-' . $wakoraStCtx->getSpanId() . '-01"', false);
            $wakoraStDone = true;
        }
    } catch (\Throwable $wakoraStErr) {
    }
};
try {
    if (isset($_SERVER['REQUEST_METHOD']) && !isset($GLOBALS['wakoraRootSpan'])) {
        $wakoraScript = isset($_SERVER['SCRIPT_FILENAME']) ? (string) $_SERVER['SCRIPT_FILENAME'] : '';
        $wakoraScriptDir = $wakoraScript !== '' ? dirname($wakoraScript) : '';
        $wakoraIsWp = $wakoraScriptDir !== '' && (
            @file_exists($wakoraScriptDir . '/wp-settings.php')
            || @file_exists(dirname($wakoraScriptDir) . '/wp-settings.php')
        );
        if ($wakoraIsWp && PHP_SAPI !== 'cli') {
            foreach (['plugins_loaded', 'init', 'template_redirect'] as $wakoraStHook) {
                $GLOBALS['wp_filter'][$wakoraStHook][PHP_INT_MAX][] = [
                    'function' => $wakoraStSend,
                    'accepted_args' => 0,
                ];
            }
        }
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
                                            $wakoraT0 = microtime(true);
                                            try {
                                                return $wakoraOrig(...$wakoraArgs);
                                            } finally {
                                                if ((microtime(true) - $wakoraT0) * 1000 >= 1.0 && $wakoraBudget->spans > 0) {
                                                    $wakoraBudget->spans--;
                                                    $wakoraTracer->spanBuilder('hook:' . $wakoraTag)
                                                        ->setStartTimestamp((int) ($wakoraT0 * 1000000000))
                                                        ->setAttribute('code.function', $wakoraCbName)
                                                        ->setAttribute('code.filepath', $wakoraCbFile)
                                                        ->startSpan()
                                                        ->end();
                                                }
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
            $wakoraStSend();
        }
    }
} catch (\Throwable $wakoraRootErr) {
}
try {
    if (PHP_SAPI !== 'cli' && function_exists('header_register_callback')) {
        header_register_callback($wakoraStSend);
    }
} catch (\Throwable $wakoraStRegErr) {
}
try {
    $wakoraRumDest = isset($_SERVER['HTTP_SEC_FETCH_DEST']) ? (string) $_SERVER['HTTP_SEC_FETCH_DEST'] : '';
    $wakoraRumAccept = isset($_SERVER['HTTP_ACCEPT']) ? (string) $_SERVER['HTTP_ACCEPT'] : '';
    $wakoraRumIsDoc = $wakoraRumDest === 'document'
        || ($wakoraRumDest === '' && stripos($wakoraRumAccept, 'text/html') !== false);
    if (isset($_SERVER['REQUEST_METHOD'], $_SERVER['HTTP_HOST'])
        && $_SERVER['REQUEST_METHOD'] === 'GET'
        && $wakoraRumIsDoc
        && !isset($_SERVER['HTTP_X_REQUESTED_WITH'])
        && (!isset($_SERVER['HTTP_ACCEPT']) || strpos((string) $_SERVER['HTTP_ACCEPT'], 'text/event-stream') === false)) {
        $wakoraRumUri = isset($_SERVER['REQUEST_URI']) ? (string) $_SERVER['REQUEST_URI'] : '/';
        if (strncmp($wakoraRumUri, '/wp-admin', 9) !== 0 && strncmp($wakoraRumUri, '/wp-login', 9) !== 0) {
            $wakoraRumSites = @include dirname(__DIR__) . '/rum-sites.php';
            if (is_array($wakoraRumSites) && count($wakoraRumSites)) {
                $wakoraRumSite = strtolower((string) $_SERVER['HTTP_HOST']);
                $wakoraRumP = strpos($wakoraRumSite, ':');
                if ($wakoraRumP !== false) {
                    $wakoraRumSite = substr($wakoraRumSite, 0, $wakoraRumP);
                }
                if (strncmp($wakoraRumSite, 'www.', 4) === 0) {
                    $wakoraRumSite = substr($wakoraRumSite, 4);
                }
                if (isset($wakoraRumSites[$wakoraRumSite])) {
                    $wakoraRumSnippet = <<<'WAKORARUMJS'
<script data-wakora-rum>(function(){try{var v={},e=[],sent=0,clks=[],fr=[],cr=[],t0=Date.now(),lc=null;var nav=performance.getEntriesByType("navigation")[0];if(nav){v.ttfb=Math.round(nav.responseStart)}
try{new PerformanceObserver(function(l){var s=l.getEntries();if(s.length)v.lcp=Math.round(s[s.length-1].startTime)}).observe({type:"largest-contentful-paint",buffered:true})}catch(_){}
try{var c=0;new PerformanceObserver(function(l){l.getEntries().forEach(function(x){if(!x.hadRecentInput)c+=x.value});v.cls=Math.round(c*1000)/1000}).observe({type:"layout-shift",buffered:true})}catch(_){}
try{var i=0;new PerformanceObserver(function(l){l.getEntries().forEach(function(x){if(x.duration>i){i=x.duration;v.inp=Math.round(i)}})}).observe({type:"event",buffered:true,durationThreshold:40})}catch(_){}
try{new PerformanceObserver(function(l){l.getEntries().forEach(function(x){if(x.name==="first-contentful-paint")v.fcp=Math.round(x.startTime)})}).observe({type:"paint",buffered:true})}catch(_){}
function tok(t){t=String(t||"");if(!t||t.length>32)return "";if(/[^A-Za-z0-9_-]/.test(t))return "";var d=t.replace(/[^0-9]/g,"").length;if(d&&d/t.length>0.4)return "";if(/^[0-9a-f]{8,}$/i.test(t))return "";return t}
function sel(el){var p=[],n=0;while(el&&el.nodeType===1&&n<3){var t=String(el.tagName||"").toLowerCase();if(!t)break;var s=t,id=tok(el.id),stop=0;if(id){s+="#"+id;stop=1}else{var cn=(typeof el.className==="string")?tok(el.className.split(/\s+/)[0]):"";if(cn)s+="."+cn;else{var q=el.parentNode,ix=1,j;if(q&&q.children)for(j=0;j<q.children.length;j++)if(q.children[j]===el){ix=j+1;break}s+=":nth-child("+ix+")"}}p.unshift(s);if(stop)break;el=el.parentNode;n++}return p.join(">").slice(0,120)}
function npath(u){var p=String(u||"");try{if(p.indexOf("://")>0){var a=document.createElement("a");a.href=p;p=(a.hostname===location.hostname?"":a.hostname)+a.pathname}}catch(_){}return p.split("?")[0].replace(/\/\d+/g,"/:n").replace(/\/[0-9a-f]{8,}/gi,"/:x").slice(0,120)}
function crumb(k,s,st,d){if(cr.length>=30)cr.shift();var o={t:Date.now()-t0,k:k,s:String(s||"").slice(0,120)};if(st)o.st=st;if(d)o.d=d;cr.push(o)}
function frust(n,s,c){var i;for(i=0;i<fr.length;i++){if(fr[i].name===n&&fr[i].sel===s){if(c>fr[i].count)fr[i].count=c;return}}if(fr.length<5)fr.push({name:n,sel:s,count:c})}
function errClick(){if(lc&&Date.now()-lc.t<=1000)frust("error_click",lc.s,1)}
function crj(){var a=cr.slice(0),s="";try{s=JSON.stringify(a);while(s.length>2000&&a.length>1){a.shift();s=JSON.stringify(a)}}catch(_){s=""}return s}
addEventListener("click",function(ev){try{var t=Date.now(),x=ev.clientX,y=ev.clientY,s=sel(ev.target),n=0,i;crumb("c",s);clks.push({t:t,x:x,y:y});if(clks.length>8)clks.shift();for(i=0;i<clks.length;i++){var k=clks[i];if(t-k.t<=1000&&Math.abs(k.x-x)<=30&&Math.abs(k.y-y)<=30)n++}if(n>=3)frust("rage",s,n);lc={t:t,s:s}}catch(_){}},true);
addEventListener("popstate",function(){try{crumb("n",npath(location.pathname))}catch(_){}});
try{new PerformanceObserver(function(l){l.getEntries().forEach(function(x){var it=x.initiatorType;if(it!=="fetch"&&it!=="xmlhttprequest")return;crumb("f",npath(x.name),x.responseStatus||0,Math.round(x.duration||0))})}).observe({type:"resource",buffered:true})}catch(_){}
addEventListener("error",function(ev){errClick();if(e.length<10)e.push({msg:String(ev.message||"error").slice(0,200),src:(ev.filename?ev.filename+":"+(ev.lineno||0):"").slice(0,120),n:1})});
addEventListener("unhandledrejection",function(ev){errClick();if(e.length<10){var st="";try{st=ev.reason&&ev.reason.stack?String(ev.reason.stack).split("\n").slice(1,3).join(" ").replace(/\s+/g," ").trim():""}catch(_){}e.push({msg:("promise: "+String(ev.reason)).slice(0,200),src:st.slice(0,120),n:1})}});
function send(){if(sent)return;sent=1;var ua=navigator.userAgent,dev=/Mobi|Android/i.test(ua)?"mobile":(/Tablet|iPad/i.test(ua)?"tablet":"desktop");
var bw=/Edg\//.test(ua)?"edge":(/OPR\//.test(ua)?"opera":(/Chrome\//.test(ua)?"chrome":(/Firefox\//.test(ua)?"firefox":(/Safari\//.test(ua)?"safari":"other"))));
var tr="";try{var st=(nav&&nav.serverTiming)||[];for(var q=0;q<st.length;q++){if(st[q].name==="traceparent"){var pd=String(st[q].description||"").split("-");if(pd.length>1)tr=pd[1];break}}}catch(_){}
var cj=(e.length&&cr.length)?crj():"";
try{navigator.sendBeacon("/?wkr-rum=1",JSON.stringify({site:location.hostname,path:location.pathname,dev:dev,browser:bw,trace:tr,vitals:v,errors:e,frust:fr,crumbs:cj}))}catch(_){}}
addEventListener("pagehide",send);document.addEventListener("visibilitychange",function(){if(document.visibilityState==="hidden")send()});
}catch(_){}})();</script>
WAKORARUMJS;
                    ob_start(static function ($wakoraHtml) use ($wakoraRumSnippet) {
                        try {
                            if (!is_string($wakoraHtml) || $wakoraHtml === '' || strpos($wakoraHtml, 'data-wakora-rum') !== false) {
                                return $wakoraHtml;
                            }
                            if (strpos($wakoraHtml, 'rum.wakora.io/w.js') !== false) {
                                return $wakoraHtml;
                            }
                            foreach (headers_list() as $wakoraRumH) {
                                if (stripos($wakoraRumH, 'content-type:') === 0 && stripos($wakoraRumH, 'text/html') === false) {
                                    return $wakoraHtml;
                                }
                            }
                            $wakoraRumPos = stripos($wakoraHtml, '</head>');
                            if ($wakoraRumPos === false) {
                                return $wakoraHtml;
                            }
                            $wakoraRumOneLine = str_replace(["\r", "\n"], '', $wakoraRumSnippet);
                            return substr($wakoraHtml, 0, $wakoraRumPos) . "\n" . $wakoraRumOneLine . "\n" . substr($wakoraHtml, $wakoraRumPos);
                        } catch (\Throwable $wakoraRumCbErr) {
                            return $wakoraHtml;
                        }
                    });
                }
            }
        }
        unset($wakoraRumUri, $wakoraRumSites, $wakoraRumSite, $wakoraRumP);
    }
} catch (\Throwable $wakoraRumInjErr) {
}
