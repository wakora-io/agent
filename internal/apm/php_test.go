package apm

import "testing"

const phpInfoSample = `phpinfo()
PHP Version => 8.3.6

System => Linux buildhost 6.8.0
Thread Safety => disabled
Zend Memory Manager => enabled
`

func TestParsePHPInfo(t *testing.T) {
	rt := ParsePHPInfo(phpInfoSample)
	if rt.Version != "8.3.6" {
		t.Fatalf("version: %q", rt.Version)
	}
	if rt.VersionShort != "8.3" {
		t.Fatalf("short: %q", rt.VersionShort)
	}
	if rt.ThreadSafe {
		t.Fatal("expected NTS")
	}
	if rt.ThreadTag() != "nts" {
		t.Fatalf("tag: %q", rt.ThreadTag())
	}
}

func TestParsePHPInfoZTS(t *testing.T) {
	rt := ParsePHPInfo("PHP Version => 8.2.1\nThread Safety => enabled\n")
	if !rt.ThreadSafe || rt.ThreadTag() != "zts" {
		t.Fatalf("expected ZTS, got %v/%s", rt.ThreadSafe, rt.ThreadTag())
	}
}

func TestParsePHPInfoPrepend(t *testing.T) {
	rt := ParsePHPInfo("PHP Version => 8.1.2\nauto_prepend_file => /var/lib/wakora/apm/opentelemetry-php-sdk81/wakora-otel.php => /var/lib/wakora/apm/opentelemetry-php-sdk81/wakora-otel.php\n")
	if rt.Prepend != "/var/lib/wakora/apm/opentelemetry-php-sdk81/wakora-otel.php" {
		t.Fatalf("prepend: %q", rt.Prepend)
	}
	rt = ParsePHPInfo("PHP Version => 8.1.2\nauto_prepend_file => no value => no value\n")
	if rt.Prepend != "" {
		t.Fatalf("no value must parse empty, got %q", rt.Prepend)
	}
}

func TestOtelArtifactName(t *testing.T) {
	rt := PHPRuntime{VersionShort: "8.3", ThreadSafe: false, Arch: "amd64", Libc: "glibc"}
	want := "opentelemetry-8.3-nts-amd64-glibc.so"
	if got := OtelArtifactName(rt); got != want {
		t.Fatalf("artifact: %q", got)
	}
	if OtelArtifactName(PHPRuntime{VersionShort: "8.3"}) != "" {
		t.Fatal("incomplete fingerprint must yield empty artifact")
	}
}

func TestModuleLoaded(t *testing.T) {
	list := "[PHP Modules]\nCore\ncurl\nopentelemetry\nmysqli\n"
	if !ModuleLoaded(list, "opentelemetry") {
		t.Fatal("should detect opentelemetry")
	}
	if ModuleLoaded(list, "xdebug") {
		t.Fatal("should not detect xdebug")
	}
}

func TestOtelIni(t *testing.T) {
	ini := OtelIni("/opt/otel.so", "shop", "http://127.0.0.1:4318", "", "abc123")
	for _, want := range []string{"extension=/opt/otel.so", "otel.service.name=shop", "otel.exporter.otlp.endpoint=http://127.0.0.1:4318"} {
		if !contains(ini, want) {
			t.Fatalf("ini missing %q in:\n%s", want, ini)
		}
	}
}

func TestPHPSDKBundleFor(t *testing.T) {
	cases := map[string]string{
		"8.1":  "opentelemetry-php-sdk81",
		"8.2":  "opentelemetry-php-sdk",
		"8.3":  "opentelemetry-php-sdk",
		"8.4":  "opentelemetry-php-sdk",
		"8.10": "opentelemetry-php-sdk",
		"9.0":  "opentelemetry-php-sdk",
		"8.0":  "",
		"7.4":  "",
		"junk": "",
	}
	for ver, want := range cases {
		if got := PHPSDKBundleFor(ver); got != want {
			t.Errorf("PHPSDKBundleFor(%s) = %q, want %q", ver, got, want)
		}
	}
}

func TestOtelSupported(t *testing.T) {
	for ver, want := range map[string]bool{
		"8.1": true, "8.2": true, "8.4": true, "9.0": true,
		"8.0": false, "7.4": false, "7.2": false, "junk": false,
	} {
		if got := OtelSupported(ver); got != want {
			t.Errorf("OtelSupported(%s) = %v, want %v", ver, got, want)
		}
	}
}

func TestOtelIniWithSDK(t *testing.T) {
	ini := OtelIni("/opt/otel.so", "shop", "http://127.0.0.1:4318", "/var/lib/wakora/apm/opentelemetry-php-sdk", "")
	for _, want := range []string{
		"extension=/opt/otel.so",
		"auto_prepend_file=/var/lib/wakora/apm/opentelemetry-php-sdk/wakora-otel.php",
		"wakora.otel_service=shop",
		"wakora.otel_endpoint=http://127.0.0.1:4318",
	} {
		if !contains(ini, want) {
			t.Fatalf("ini missing %q in:\n%s", want, ini)
		}
	}
	if contains(ini, "otel.traces.exporter") {
		t.Fatal("legacy keys must not appear in sdk mode")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
