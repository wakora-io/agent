<?php

return [
    'prefix' => 'WakoraOtel',
    'exclude-namespaces' => [
        'OpenTelemetry\Instrumentation',
        'Google\Protobuf',
        'GPBMetadata',
        'Opentelemetry\Proto',
    ],
    'exclude-classes' => [
        'WP_Hook',
    ],
    'exclude-functions' => [
        'add_action',
    ],
];
