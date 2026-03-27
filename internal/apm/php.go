package apm

import (
	"fmt"
	"strconv"
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

const PHPSDKBundle = "opentelemetry-php-sdk"

func PHPSDKBundleFor(versionShort string) string {
	major, minor, ok := splitMinor(versionShort)
	if !ok {
		return ""
	}
	switch {
	case major == 8 && minor == 1:
		return PHPSDKBundle + "81"
	case major == 8 && minor >= 2:
		return PHPSDKBundle
	case major >= 9:
		return PHPSDKBundle
	}
	return ""
}

func OtelSupported(versionShort string) bool {
	major, _, ok := splitMinor(versionShort)
	return ok && major >= 8
}

func splitMinor(versionShort string) (major, minor int, ok bool) {
	parts := strings.SplitN(versionShort, ".", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}
	minor, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, false
	}
	return major, minor, true
}

func OtelIni(soPath, serviceName, endpoint, sdkDir, artifactSha string) string {
	var b strings.Builder
	if artifactSha != "" {
		fmt.Fprintf(&b, "; wakora-artifact-sha %s\n", artifactSha)
	}
	fmt.Fprintf(&b, "extension=%s\n", soPath)
	if sdkDir != "" {
		fmt.Fprintf(&b, "auto_prepend_file=%s/wakora-otel.php\n", sdkDir)
		fmt.Fprintf(&b, "wakora.otel_service=%s\n", serviceName)
		fmt.Fprintf(&b, "wakora.otel_endpoint=%s\n", endpoint)
		return b.String()
	}
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
