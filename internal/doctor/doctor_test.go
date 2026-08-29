package doctor

import (
	"strings"
	"testing"
	"time"
)

func TestHostPort(t *testing.T) {
	cases := map[string][2]string{
		"wss://eu.gw.wakora.io:8443/ws": {"eu.gw.wakora.io", "8443"},
		"wss://eu.gw.wakora.io/ws":      {"eu.gw.wakora.io", "443"},
		"https://x.example.com:9000":    {"x.example.com", "9000"},
		"":                              {"", "8443"},
	}
	for in, want := range cases {
		h, p := hostPort(in)
		if h != want[0] || p != want[1] {
			t.Fatalf("hostPort(%q) = %q,%q want %q,%q", in, h, p, want[0], want[1])
		}
	}
}

func TestFlowFromStatus(t *testing.T) {
	fresh := flowFromStatus(status{LastAckAt: time.Now().Add(-30 * time.Second).Unix()})
	if fresh.State != Ok {
		t.Fatalf("fresh ack should be ok, got %v %q", fresh.State, fresh.Detail)
	}
	stale := flowFromStatus(status{LastAckAt: time.Now().Add(-2 * time.Hour).Unix()})
	if stale.State != Warn {
		t.Fatalf("2h-old ack should warn, got %v", stale.State)
	}
	none := flowFromStatus(status{LastAckAt: 0})
	if none.State != Warn {
		t.Fatalf("no ack should warn, got %v", none.State)
	}
}

func TestDNSVerdicts(t *testing.T) {
	if c := checkDNS(""); c.State != Fail {
		t.Fatalf("empty host must FAIL")
	}
	if c := checkDNS("203.0.113.7"); c.State != Ok || !strings.Contains(c.Detail, "literal") {
		t.Fatalf("ip literal must be ok, got %v %q", c.State, c.Detail)
	}
	if c := checkDNS("nonexistent.invalid."); c.State != Fail {
		t.Fatalf("bogus host must FAIL, got %v", c.State)
	}
}

func TestSkipChainOnDNSFail(t *testing.T) {
	in := Input{Endpoint: "wss://nonexistent.invalid.:8443/ws", ConfigDir: t.TempDir(), StateDir: t.TempDir()}
	checks := Run(in)
	got := map[string]State{}
	for _, c := range checks {
		got[c.Name] = c.State
	}
	if got["dns"] != Fail {
		t.Fatalf("dns should FAIL, got %v", got["dns"])
	}
	for _, name := range []string{"tcp 8443", "tls", "auth", "data flow"} {
		if got[name] != Skip {
			t.Fatalf("%s should be skipped after dns fail, got %v", name, got[name])
		}
	}
}

func TestIdentityNotRegistered(t *testing.T) {
	in := Input{ConfigDir: t.TempDir()}
	c := checkIdentity(in)
	if c.State != Warn || !strings.Contains(c.Detail, "not registered") {
		t.Fatalf("empty dir must read not-registered, got %v %q", c.State, c.Detail)
	}
}

func TestRenderCarriesNextStepOnFail(t *testing.T) {
	out := Render([]Check{
		{Name: "tls", State: Fail, Detail: "pin mismatch", Next: "ask IT to exempt the endpoint from inspection"},
		{Name: "dns", State: Ok, Detail: "resolves", Next: "should not print"},
	})
	if !strings.Contains(out, "FAIL") || !strings.Contains(out, "->") || !strings.Contains(out, "ask IT") {
		t.Fatalf("fail row must carry its next step:\n%s", out)
	}
	if strings.Contains(out, "should not print") {
		t.Fatal("ok rows must not print a next step")
	}
}

func TestWorst(t *testing.T) {
	if Worst([]Check{{State: Ok}, {State: Warn}, {State: Info}}) != Warn {
		t.Fatal("warn should win over ok/info")
	}
	if Worst([]Check{{State: Warn}, {State: Fail}}) != Fail {
		t.Fatal("fail should win")
	}
	if Worst([]Check{{State: Ok}, {State: Skip}}) != Ok {
		t.Fatal("ok/skip only should be ok")
	}
}

func TestRedactLine(t *testing.T) {
	cases := []string{
		"Authorization: Bearer abc123def",
		"api_key=SECRETVALUE123",
		"password: hunter2hunter2",
	}
	for _, in := range cases {
		if got := redactLine(in); strings.Contains(got, "abc123def") || strings.Contains(got, "SECRETVALUE123") || strings.Contains(got, "hunter2hunter2") {
			t.Fatalf("redactLine left a secret: %q -> %q", in, got)
		}
	}
}
