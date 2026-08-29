//go:build linux

package metrics

import "testing"

func TestParseProcStat(t *testing.T) {
	line := "1234 (php-fpm: pool www) S 1 1234 1234 0 -1 4194624 12345 0 0 0 250 130 0 0 20 0 1 0 12345678 123456789 4321 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 3 0 0 0 0 0"
	comm, ticks, rss, ok := parseProcStat(line)
	if !ok {
		t.Fatal("parse failed")
	}
	if comm != "php-fpm: pool www" {
		t.Fatalf("comm %q", comm)
	}
	if ticks != 380 {
		t.Fatalf("ticks %d, want 380", ticks)
	}
	if rss != 4321 {
		t.Fatalf("rss %d, want 4321", rss)
	}
}

func TestProcIOBytes(t *testing.T) {
	raw := "rchar: 999\nwchar: 999\nread_bytes: 4096\nwrite_bytes: 8192\ncancelled_write_bytes: 0\n"
	if n := procIOBytes(raw); n != 12288 {
		t.Fatalf("io %d, want 12288", n)
	}
}
