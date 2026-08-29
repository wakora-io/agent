package defs

import "testing"

func TestExpandDashRange(t *testing.T) {
	ips, err := expandTargets([]string{"192.0.2.85-192.0.2.90"})
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 6 || ips[0] != "192.0.2.85" || ips[5] != "192.0.2.90" {
		t.Fatalf("dash range: %v", ips)
	}
}

func TestExpandShortDashRange(t *testing.T) {
	ips, err := expandTargets([]string{"192.0.2.85-88"})
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 4 || ips[3] != "192.0.2.88" {
		t.Fatalf("short dash range: %v", ips)
	}
}

func TestExpandCIDR(t *testing.T) {
	ips, err := expandTargets([]string{"192.0.2.88/30"})
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 4 {
		t.Fatalf("cidr /30 should be 4 addrs: %v", ips)
	}
}

func TestExpandDedupsAndRejectsWide(t *testing.T) {
	ips, err := expandTargets([]string{"10.0.0.1", "10.0.0.1"})
	if err != nil || len(ips) != 1 {
		t.Fatalf("dedup failed: %v %v", ips, err)
	}
	if _, err := expandTargets([]string{"10.0.0.0/16"}); err == nil {
		t.Fatal("must reject a range wider than 256 hosts")
	}
}

func TestExpandRejectsGarbage(t *testing.T) {
	if _, err := expandTargets([]string{"not-an-ip"}); err == nil {
		t.Fatal("garbage target accepted")
	}
}
