package defs

import "testing"

func TestOtlpLoopbackPort(t *testing.T) {
	cases := []struct {
		endpoint string
		port     int
		ok       bool
	}{
		{"", 4318, true},
		{"http://127.0.0.1:4318", 4318, true},
		{"http://localhost:4319", 4319, true},
		{"http://127.0.0.1", 4318, true},
		{"http://collector.internal:4318", 0, false},
		{"http://10.0.0.5:4318", 0, false},
		{"://bad", 0, false},
	}
	for _, c := range cases {
		port, ok := otlpLoopbackPort(c.endpoint)
		if ok != c.ok || (ok && port != c.port) {
			t.Errorf("otlpLoopbackPort(%q) = %d,%v want %d,%v", c.endpoint, port, ok, c.port, c.ok)
		}
	}
}

func TestEnsureOTLPForWiresCallback(t *testing.T) {
	orig := OTLPEnsure
	defer func() { OTLPEnsure = orig }()
	got := 0
	OTLPEnsure = func(port int) { got = port }
	ensureOTLPFor("")
	if got != 4318 {
		t.Fatalf("default endpoint must ensure 4318, got %d", got)
	}
	got = 0
	ensureOTLPFor("http://collector.internal:4318")
	if got != 0 {
		t.Fatal("remote collector endpoint must not start a local receiver")
	}
}
