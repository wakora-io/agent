package apm

import "strings"

func NodeEnv(register, serviceName, endpoint, existingOptions string, perf bool) map[string]string {
	opts := "--require " + register
	if existingOptions != "" {
		opts = existingOptions + " " + opts
	}
	if perf {
		opts += " --perf-basic-prof-only-functions"
	}
	m := map[string]string{
		"NODE_OPTIONS":                opts,
		"OTEL_EXPORTER_OTLP_ENDPOINT": endpoint,
		"OTEL_TRACES_EXPORTER":        "otlp",
		"OTEL_METRICS_EXPORTER":       "otlp",
	}
	if serviceName != "" {
		m["OTEL_SERVICE_NAME"] = serviceName
	}
	return m
}

func NodeEnvActive(environ string) bool {
	return strings.Contains(environ, "wakora-register.js")
}
