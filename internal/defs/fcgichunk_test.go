package defs

import (
	"os"
	"strconv"
	"testing"
	"time"

	"wakora.io/agent/internal/protocol"
)

func TestFastCGIChunksInheritTheirHeadLevel(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/error.log"
	if err := os.WriteFile(path, []byte("seed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	l := NewLogTailer("nginx/error")
	defer l.CloseFDs()
	now := time.Date(2026, 10, 2, 14, 33, 30, 0, time.Local)
	p := protocol.Probe{Type: "logs", Paths: []string{path}, LevelRegex: `\[(error|warn|crit)\]`, MinLevel: "notice"}
	if lines, _ := l.Collect("nginx", p, now); len(lines) != 0 {
		t.Fatalf("seed collect returned %d lines", len(lines))
	}
	body := "seed\n" +
		`2026/10/02 14:33:08 [error] 7101#7101: *4100 FastCGI sent in stderr: "PHP message: PHP Warning:  Undefined array key "DEBUG" in /www/example.com/www/lib/debug.php on line 66; PHP message: PHP Warni` + "\n" +
		`2026/10/02 14:33:08 [error] 7101#7101: *4100 FastCGI sent in stderr: "ng:  Undefined array key "DEBUG" in /www/example.com/www/lib/debug.php on line 66" while reading upstream, client: 203.0.113.30, server: example.com` + "\n" +
		`2026/10/02 14:33:09 [error] 7101#7101: *4100 FastCGI sent in stderr: "; PHP message: PHP Fatal error:  Uncaught Error: Call to undefined function render() in /www/example.com/www/lib/css.php:93` + "\n" +
		`2026/10/02 14:33:10 [error] 7102#7102: *4200 FastCGI sent in stderr: "EBUG" in /www/example.org/www/lib/debug.php on line 66" while reading upstream, client: 203.0.113.31, server: example.org` + "\n" +
		`2026/10/02 14:33:11 [error] 7103#7103: *4300 FastCGI sent in stderr: "PHP message: PHP Warning:  Undefined variable $x in /www/example.net/www/index.php on line 3` + "\n" +
		`2026/10/02 14:33:25 [error] 7103#7103: *4300 FastCGI sent in stderr: "line 3" while reading upstream, client: 203.0.113.32, server: example.net` + "\n" +
		`2026/10/02 14:33:26 [error] 7104#7104: *4400 connect() to unix:/run/php/example.sock failed (2: No such file or directory) while connecting to upstream` + "\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	lines, _ := l.Collect("nginx", p, now)
	want := []string{"warn", "warn", "error", "error", "warn", "error", "error"}
	if len(lines) != len(want) {
		t.Fatalf("got %d lines, want %d: %v", len(lines), len(want), lines)
	}
	for i, w := range want {
		if lines[i].Level != w {
			t.Fatalf("line %d level %q, want %q: %s", i, lines[i].Level, w, lines[i].Message)
		}
	}
}

func TestFastCGIChunkMemoryStaysBounded(t *testing.T) {
	l := NewLogTailer("nginx/error")
	for i := 0; i < fcgiPrevCap*3; i++ {
		raw := "2026/10/02 14:33:08 [error] 1#1: *" + strconv.Itoa(i) + ` FastCGI sent in stderr: "PHP message: PHP Warning:  x`
		l.fcgiChunkLevel("p", raw, "warn", int64(i))
	}
	if len(l.fcgiPrev) > fcgiPrevCap {
		t.Fatalf("memory grew to %d entries", len(l.fcgiPrev))
	}
}
