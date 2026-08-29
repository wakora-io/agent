package defs

import "testing"

func TestScaleOID(t *testing.T) {
	if got := scaleOID(540, 0.1); got != 54 {
		t.Fatalf("deci-degrees not scaled: %v", got)
	}
	if got := scaleOID(540, 0); got != 540 {
		t.Fatalf("no scale must pass the raw value: %v", got)
	}
}

func TestVhostCatchAll(t *testing.T) {
	for _, n := range []string{"_", "", "localhost", "203.0.113.10", "hostname-without-dots", "2001:db8::1"} {
		if !vhostCatchAll(n) {
			t.Fatalf("%q must be a catch-all entry, not a site", n)
		}
	}
	for _, n := range []string{"example.com", "www.example.com", "shop.sub.example.org", "site.local"} {
		if vhostCatchAll(n) {
			t.Fatalf("%q is a real site", n)
		}
	}
}
