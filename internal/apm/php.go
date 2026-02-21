package apm

import (
	"fmt"
	"strings"
)

type PHPRuntime struct {
	Version      string
	VersionShort string
	ThreadSafe   bool
	Arch         string
	Libc         string
	ScanDir      string
}

func ParsePHPInfo(out string) PHPRuntime {
	rt := PHPRuntime{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if v, ok := cutInfo(line, "PHP Version"); ok && rt.Version == "" {
			rt.Version = v
			rt.VersionShort = shortVersion(v)
			continue
		}
		if v, ok := cutInfo(line, "Thread Safety"); ok {
			rt.ThreadSafe = strings.EqualFold(v, "enabled")
			continue
		}
		if v, ok := cutInfo(line, "Scan this dir for additional .ini files"); ok && rt.ScanDir == "" {
			if v != "(none)" {
				rt.ScanDir = firstPath(v)
			}
			continue
		}
	}
	return rt
}

func firstPath(v string) string {
	if i := strings.IndexAny(v, ",\n"); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}

func cutInfo(line, key string) (string, bool) {
	if !strings.HasPrefix(line, key) {
		return "", false
	}
	rest := strings.TrimPrefix(line, key)
	rest = strings.TrimSpace(rest)
	rest = strings.TrimPrefix(rest, "=>")
	return strings.TrimSpace(rest), true
}

func shortVersion(v string) string {
	parts := strings.Split(v, ".")
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return v
}

func MinorVersion(v string) string {
	return shortVersion(v)
}

func (r PHPRuntime) ThreadTag() string {
	if r.ThreadSafe {
		return "zts"
	}
	return "nts"
}

func OtelArtifactName(r PHPRuntime) string {
	if r.VersionShort == "" || r.Arch == "" || r.Libc == "" {
		return ""
	}
	return fmt.Sprintf("opentelemetry-%s-%s-%s-%s.so", r.VersionShort, r.ThreadTag(), r.Arch, r.Libc)
}

func OtelIni(soPath, serviceName, endpoint string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "extension=%s\n", soPath)
	fmt.Fprintf(&b, "otel.service.name=%s\n", serviceName)
	fmt.Fprintf(&b, "otel.exporter.otlp.endpoint=%s\n", endpoint)
	b.WriteString("otel.traces.exporter=otlp\n")
	b.WriteString("otel.metrics.exporter=none\n")
	b.WriteString("otel.logs.exporter=none\n")
	return b.String()
}

func ModuleLoaded(moduleList, name string) bool {
	for _, line := range strings.Split(moduleList, "\n") {
		if strings.EqualFold(strings.TrimSpace(line), name) {
			return true
		}
	}
	return false
}
