package apm

import "strings"

func NodeEnv(register, serviceName, endpoint, existingOptions string) map[string]string {
	opts := "--require " + register
	if existingOptions != "" {
		opts = existingOptions + " " + opts
	}
	m := map[string]string{
		"NODE_OPTIONS":                opts,
		"OTEL_EXPORTER_OTLP_ENDPOINT": endpoint,
	}
	if serviceName != "" {
		m["OTEL_SERVICE_NAME"] = serviceName
	}
	return m
}

func NodeEnvActive(environ string) bool {
	return strings.Contains(environ, "wakora-register.js")
}
