//go:build linux

package discovery

import "testing"

func TestDecodeAddr(t *testing.T) {
	cases := map[string]string{
		"0100007F":                         "127.0.0.1",
		"00000000":                         "0.0.0.0",
		"00000000000000000000000000000000": "::",
	}
	for in, want := range cases {
		if got := decodeAddr(in); got != want {
			t.Fatalf("decodeAddr(%q) = %q, want %q", in, got, want)
		}
	}
	if got := decodeAddr("fe800000000000000000000000000001"); got != "ipv6" {
		t.Fatalf("v6 fallback: %q", got)
	}
}

func TestParseCronLine(t *testing.T) {
	sched, user, cmd, ok := parseCronLine("17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly", "", true)
	if !ok || sched != "17 * * * *" || user != "root" || cmd != "cd / && run-parts --report /etc/cron.hourly" {
		t.Fatalf("system line: %q %q %q %v", sched, user, cmd, ok)
	}
	sched, user, cmd, ok = parseCronLine("*/5 * * * * /usr/local/bin/backup.sh", "olga", false)
	if !ok || sched != "*/5 * * * *" || user != "olga" || cmd != "/usr/local/bin/backup.sh" {
		t.Fatalf("spool line: %q %q %q %v", sched, user, cmd, ok)
	}
	sched, user, cmd, ok = parseCronLine("@daily root /opt/dump.sh", "", true)
	if !ok || sched != "@daily" || user != "root" || cmd != "/opt/dump.sh" {
		t.Fatalf("@daily line: %q %q %q %v", sched, user, cmd, ok)
	}
	for _, bad := range []string{"", "# comment", "SHELL=/bin/sh", "MAILTO=root", "* * * *"} {
		if _, _, _, ok := parseCronLine(bad, "", true); ok {
			t.Fatalf("accepted junk line %q", bad)
		}
	}
}

func TestParseApkDB(t *testing.T) {
	db := "C:Q1abc\nP:musl\nV:1.2.5-r1\nA:x86_64\n\nC:Q2def\nP:busybox\nV:1.36.1-r29\n\nP:openrc\nV:0.54-r1\n"
	facts := parseApkDB(db)
	if len(facts) != 3 {
		t.Fatalf("want 3 packages, got %d: %+v", len(facts), facts)
	}
	if facts[0].Key != "busybox" || facts[1].Key != "musl" || facts[2].Key != "openrc" {
		t.Fatalf("wrong names/order: %+v", facts)
	}
	if facts[1].Payload != `{"version":"1.2.5-r1"}` {
		t.Fatalf("musl version payload: %s", facts[1].Payload)
	}
}
