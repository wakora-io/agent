package discovery

import "testing"

func TestParsePidColumnKeepsSpacesInTheName(t *testing.T) {
	out := "  412 /Applications/Google Chrome.app/Contents/MacOS/Google Chrome\n   88 /usr/sbin/syslogd\n\n  x broken\n"
	m := parsePidColumn(out)
	if m[412] != "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" {
		t.Fatalf("name with spaces cut: %q", m[412])
	}
	if m[88] != "/usr/sbin/syslogd" || len(m) != 2 {
		t.Fatalf("parse: %v", m)
	}
}
