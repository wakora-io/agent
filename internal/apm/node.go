package apm

import "strings"

func NodeEnv(register, serviceName, endpoint string) map[string]string {
	return map[string]string{
		"NODE_OPTIONS":                "--require " + register,
		"OTEL_SERVICE_NAME":           serviceName,
		"OTEL_EXPORTER_OTLP_ENDPOINT": endpoint,
	}
}

func NodeEnvActive(environ string) bool {
	return strings.Contains(environ, "wakora-register.js")
}
