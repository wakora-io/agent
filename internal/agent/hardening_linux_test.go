//go:build linux

package agent

import (
	"strings"
	"testing"
)

func TestUnitUnhardenedOnlyWithoutProtectSystem(t *testing.T) {
	if !unitUnhardened("no") {
		t.Fatal("a unit without ProtectSystem needs the drop-in")
	}
	for _, v := range []string{"full", "strict", "yes", ""} {
		if unitUnhardened(v) {
			t.Fatalf("ProtectSystem=%q must be left alone", v)
		}
	}
}

func TestSystemdVersionParsesTheFirstLine(t *testing.T) {
	cases := map[string]int{
		"systemd 255 (255.4-1ubuntu8)\n+PAM +AUDIT": 255,
		"systemd 219\n+PAM":                         219,
		"garbage":                                   0,
		"":                                          0,
	}
	for in, want := range cases {
		if got := systemdVersion(in); got != want {
			t.Fatalf("systemdVersion(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestHardeningBodyKeepsTheAgentWritableAndSetsNoMemoryLimit(t *testing.T) {
	body := hardeningBody("/usr/local/bin")
	for _, want := range []string{"ProtectSystem=full", "ProtectHome=read-only", "ProtectControlGroups=yes", "-/etc/wakora", "-/var/lib/wakora", "-/var/log/wakora", "-/usr/local/bin"} {
		if !strings.Contains(body, want) {
			t.Fatalf("drop-in lacks %q:\n%s", want, body)
		}
	}
	if strings.Count(body, "-/usr/local/bin") != 1 {
		t.Fatalf("the binary directory must appear once:\n%s", body)
	}
	if strings.Contains(body, "Memory") {
		t.Fatalf("the drop-in must never carry a memory limit:\n%s", body)
	}
}

func TestHardeningBodyAddsANonStandardBinaryDirectory(t *testing.T) {
	body := hardeningBody("/opt/wakora")
	if !strings.Contains(body, "-/opt/wakora") {
		t.Fatalf("self-update writes next to the binary, its directory must stay writable:\n%s", body)
	}
}
