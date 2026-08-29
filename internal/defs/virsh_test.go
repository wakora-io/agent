package defs

import "testing"

func TestParseVirshPools(t *testing.T) {
	out := ` Name      State     Autostart   Persistent   Capacity    Allocation   Available
-----------------------------------------------------------------------------------
 default   running   yes         yes          98.31 GiB   23.70 GiB    74.61 GiB
 iso       running   yes         yes          10.00 GiB   9.50 GiB     0.50 GiB
 dead      inactive  no          yes          -           -            -
`
	pools := parseVirshPools(out)
	if len(pools) != 2 {
		t.Fatalf("expected 2 running pools, got %d", len(pools))
	}
	d := pools["default"]
	if d == nil {
		t.Fatal("default pool missing")
	}
	wantCap := 98.31 * (1 << 30)
	if diff := d["capacity"] - wantCap; diff > 1e6 || diff < -1e6 {
		t.Fatalf("capacity: got %f want %f", d["capacity"], wantCap)
	}
	pct := d["allocation"] / d["capacity"] * 100
	if pct < 24.0 || pct > 24.2 {
		t.Fatalf("used pct: got %f", pct)
	}
	if _, ok := pools["dead"]; ok {
		t.Fatal("inactive pool must be skipped")
	}
}
