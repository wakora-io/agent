package agent

import (
	"testing"

	"wakora.io/agent/internal/config"
)

func TestOverrideKey(t *testing.T) {
	cases := map[string]string{
		"accessLog": "access-log",
		"slowLog":   "slow-log",
		"logFile":   "log-file",
		"confFile":  "conf-file",
		"datadir":   "datadir",
	}
	for fact, want := range cases {
		if got := overrideKey(fact); got != want {
			t.Errorf("overrideKey(%q)=%q want %q", fact, got, want)
		}
	}
}

func TestLocationOverridePrecedence(t *testing.T) {
	a := &Agent{cfg: &config.Config{Overrides: map[string]map[string]string{
		"nginx": {"access-log": "/www/custom/access.log"},
		"mysql": {"slowLog": "/db/slow.log"},
	}}}
	if v, ok := a.locationOverride("nginx", "accessLog"); !ok || v != "/www/custom/access.log" {
		t.Fatalf("kebab override not resolved: %q %v", v, ok)
	}
	if v, ok := a.locationOverride("mysql", "slowLog"); !ok || v != "/db/slow.log" {
		t.Fatalf("camelCase override not resolved: %q %v", v, ok)
	}
	if _, ok := a.locationOverride("nginx", "errorLog"); ok {
		t.Fatal("resolved an override that was not set")
	}
	if _, ok := a.locationOverride("redis", "accessLog"); ok {
		t.Fatal("resolved override for a service with no section")
	}
}
