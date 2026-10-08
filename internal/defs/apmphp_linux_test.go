//go:build linux

package defs

import (
	"os"
	"path/filepath"
	"testing"

	"wakora.io/agent/internal/apm"
)

func TestOtelArtifactLineKeepsWhatAHostAlreadyRuns(t *testing.T) {
	saved := Provision
	Provision = nil
	defer func() { Provision = saved }()
	state := t.TempDir()
	dir := filepath.Join(state, "apm")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	rt := apm.PHPRuntime{VersionShort: "8.3", ThreadSafe: false, Arch: "amd64", Libc: "glibc"}
	legacy := apm.OtelArtifactName(rt)
	current := apm.OtelArtifactCurrent(rt)
	if got := otelArtifactFor(state, rt); got != legacy {
		t.Fatalf("with nothing on disk and no channel the legacy name stays, got %q", got)
	}
	if err := os.WriteFile(filepath.Join(dir, current), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := otelArtifactFor(state, rt); got != current {
		t.Fatalf("a host holding the current line uses it, got %q", got)
	}
	if err := os.WriteFile(filepath.Join(dir, legacy), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := otelArtifactFor(state, rt); got != legacy {
		t.Fatalf("a host that already runs the legacy build never moves, got %q", got)
	}
}

func TestParseModPhpMinor(t *testing.T) {
	load := []byte("# apache2 php module\nLoadModule php_module /usr/lib/apache2/modules/libphp8.3.so\n")
	if got := parseModPhpMinor(load); got != "8.3" {
		t.Fatalf("minor: %q", got)
	}
	if got := parseModPhpMinor([]byte("LoadModule mpm_prefork_module modules/mod_mpm_prefork.so")); got != "" {
		t.Fatalf("no libphp must yield empty, got %q", got)
	}
}
