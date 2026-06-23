'use strict';
try {
	var parts = process.versions.node.split('.');
	var major = parseInt(parts[0], 10);
	var minor = parseInt(parts[1], 10);
	if (major < 18 || (major === 18 && minor < 19)) return;
	if (!process.env.OTEL_EXPORTER_OTLP_ENDPOINT) return;
	if (process.env.OTEL_SDK_DISABLED === 'true') return;
	if (process.env.PM2_HOME && process.env.pm_id === undefined) return;
	if (!process.env.OTEL_SERVICE_NAME && process.env.pm_id !== undefined && process.env.name) process.env.OTEL_SERVICE_NAME = process.env.name;
	if (!process.env.OTEL_TRACES_EXPORTER) process.env.OTEL_TRACES_EXPORTER = 'otlp';
	if (!process.env.OTEL_METRICS_EXPORTER) process.env.OTEL_METRICS_EXPORTER = 'otlp';
	if (!process.env.OTEL_METRIC_EXPORT_INTERVAL) process.env.OTEL_METRIC_EXPORT_INTERVAL = '60000';
	if (!process.env.OTEL_LOGS_EXPORTER) process.env.OTEL_LOGS_EXPORTER = 'none';
	if (!process.env.OTEL_EXPORTER_OTLP_PROTOCOL) process.env.OTEL_EXPORTER_OTLP_PROTOCOL = 'http/protobuf';
	if (!process.env.OTEL_NODE_DISABLED_INSTRUMENTATIONS) process.env.OTEL_NODE_DISABLED_INSTRUMENTATIONS = 'fs,dns,net';
	if (!process.env.OTEL_NODE_RESOURCE_DETECTORS) process.env.OTEL_NODE_RESOURCE_DETECTORS = 'env,host,os,process';
	require(require.resolve('@opentelemetry/auto-instrumentations-node/register', { paths: [__dirname] }));
} catch (e) {}
