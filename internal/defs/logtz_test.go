package defs

import (
	"os"
	"strings"
	"testing"
	"time"

	"wakora.io/agent/internal/protocol"
)

func TestParseLineTsInTheServiceZone(t *testing.T) {
	moscow, err := time.LoadLocation("Europe/Moscow")
	if err != nil {
		t.Skip(err)
	}
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	line := "2026-10-10 14:55:00.123 MSK [812] LOG:  checkpoint starting: time"
	if got, want := parseLineTsIn(line, now, moscow), time.Date(2026, 10, 10, 11, 55, 0, 0, time.UTC).Unix(); got != want {
		t.Fatalf("ts %d, want %d (14:55 Moscow = 11:55 UTC)", got, want)
	}
	if got := parseLineTsIn("2026-10-10T11:55:00Z explicit zone wins", now, moscow); got != time.Date(2026, 10, 10, 11, 55, 0, 0, time.UTC).Unix() {
		t.Fatalf("an explicit zone in the line must not be reinterpreted, got %d", got)
	}
}

func TestLogLocation(t *testing.T) {
	if logLocation("") != time.Local || logLocation("localtime") != time.Local || logLocation("No/Such_Zone") != time.Local {
		t.Fatal("unknown or empty zones fall back to the machine zone")
	}
	if loc := logLocation("UTC"); loc.String() != "UTC" {
		t.Fatalf("UTC read as %s", loc)
	}
}

func TestDirTailDrainsTheOldFileAndReadsTheNewOneWhole(t *testing.T) {
	dir := t.TempDir() + "/pglog"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	old := dir + "/postgresql-Fri.log"
	if err := os.WriteFile(old, []byte("2026-10-09 23:58:00 ERROR: seed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	l := NewLogTailer("postgres/log")
	defer l.CloseFDs()
	p := protocol.Probe{Type: "logs", Paths: []string{dir}, LevelRegex: `\b(ERROR|WARNING|LOG)\b`}
	now := time.Now()
	if _, err := l.Collect("postgres", p, now); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(old, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("2026-10-09 23:59:59 ERROR: last words of the old day\n")
	f.Close()
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/postgresql-Sat.log", []byte("2026-10-10 00:00:01 ERROR: first words of the new day\n2026-10-10 00:03:00 ERROR: written before the switch was noticed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	lines, err := l.Collect("postgres", p, now.Add(dirResolveTTL+time.Second))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, ln := range lines {
		got = append(got, ln.Message)
	}
	joined := strings.Join(got, "\n")
	for _, want := range []string{"last words of the old day", "first words of the new day", "written before the switch was noticed"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q after the switch, got:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "seed") {
		t.Fatal("the backlog of the first file seen must stay skipped")
	}
}
