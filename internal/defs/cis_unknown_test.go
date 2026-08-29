//go:build linux

package defs

import "testing"

func TestLoginDefsChecksReportWhetherTheKeyWasThereAtAll(t *testing.T) {
	if ok, has := cisLoginDefsMax("PASS_MIN_DAYS 0\n", "PASS_MAX_DAYS", 365); has || ok {
		t.Fatalf("an absent key must be unknown, not a pass: ok=%v has=%v", ok, has)
	}
	if ok, has := cisLoginDefsMax("PASS_MAX_DAYS 99999\n", "PASS_MAX_DAYS", 365); !has || ok {
		t.Fatalf("a too-long max-age must fail: ok=%v has=%v", ok, has)
	}
	if ok, has := cisLoginDefsMax("PASS_MAX_DAYS 90\n", "PASS_MAX_DAYS", 365); !has || !ok {
		t.Fatalf("a compliant max-age must pass: ok=%v has=%v", ok, has)
	}
	if ok, has := cisLoginDefsUmask("# nothing here\n"); has || ok {
		t.Fatalf("an absent umask must be unknown, not a pass: ok=%v has=%v", ok, has)
	}
	if ok, has := cisLoginDefsUmask("UMASK 022\n"); !has || ok {
		t.Fatalf("a weak umask must fail: ok=%v has=%v", ok, has)
	}
	if ok, has := cisLoginDefsUmask("UMASK 027\n"); !has || !ok {
		t.Fatalf("a strict umask must pass: ok=%v has=%v", ok, has)
	}
}
