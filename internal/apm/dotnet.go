package apm

import (
	"fmt"
	"strings"
)

const dotnetProfilerGUID = "{918728DD-259F-4A6A-AC2B-B85E1B658318}"

func DotnetBundleName(osTag, arch string) string {
	if osTag == "" || arch == "" {
		return ""
	}
	return fmt.Sprintf("opentelemetry-dotnet-%s-%s", osTag, arch)
}

func DotnetEnv(bundleDir, nativeProfiler, serviceName, endpoint string) map[string]string {
	return map[string]string{
		"CORECLR_ENABLE_PROFILING":    "1",
		"CORECLR_PROFILER":            dotnetProfilerGUID,
		"CORECLR_PROFILER_PATH":       nativeProfiler,
		"DOTNET_ADDITIONAL_DEPS":      bundleDir + "/AdditionalDeps",
		"DOTNET_SHARED_STORE":         bundleDir + "/store",
		"DOTNET_STARTUP_HOOKS":        bundleDir + "/net/OpenTelemetry.AutoInstrumentation.StartupHook.dll",
		"OTEL_DOTNET_AUTO_HOME":       bundleDir,
		"OTEL_SERVICE_NAME":           serviceName,
		"OTEL_TRACES_EXPORTER":        "otlp",
		"OTEL_METRICS_EXPORTER":       "none",
		"OTEL_LOGS_EXPORTER":          "none",
		"OTEL_EXPORTER_OTLP_PROTOCOL": "http/protobuf",
		"OTEL_EXPORTER_OTLP_ENDPOINT": endpoint,
	}
}

func DotnetEnvActive(environ string) bool {
	return strings.Contains(environ, "CORECLR_ENABLE_PROFILING=1")
}
