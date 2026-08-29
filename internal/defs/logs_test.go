package defs

import (
	"os"
	"strings"
	"testing"
	"time"

	"wakora.io/agent/internal/protocol"
)

func TestParseLineTs(t *testing.T) {
	now := time.Date(2026, 7, 26, 21, 10, 0, 0, time.Local)
	cases := []struct {
		line string
		want time.Time
	}{
		{"2026/07/26 21:05:01 [error] 1#1: something broke", time.Date(2026, 7, 26, 21, 5, 1, 0, time.Local)},
		{"2026-07-26 21:05:01 0 [Warning] Aborted connection", time.Date(2026, 7, 26, 21, 5, 1, 0, time.Local)},
		{"2026-07-26T18:05:01.123456Z 0 [System] ready", time.Date(2026, 7, 26, 18, 5, 1, 0, time.UTC)},
		{"1.2.3.4 - - [26/Jul/2026:21:05:01 +0300] \"GET / HTTP/1.1\" 200", time.Date(2026, 7, 26, 18, 5, 1, 0, time.UTC)},
		{"[Sun Jul 26 21:05:01.123456 2026] [php:warn] [pid 1] msg", time.Date(2026, 7, 26, 21, 5, 1, 0, time.Local)},
		{"Jul 26 21:05:01 host postfix/smtpd[1]: connect", time.Date(2026, 7, 26, 21, 5, 1, 0, time.Local)},
	}
	for _, c := range cases {
		got := parseLineTs(c.line, now)
		if got != c.want.Unix() {
			t.Fatalf("line %q: ts %d, want %d", c.line, got, c.want.Unix())
		}
	}
	if got := parseLineTs("no timestamp here at all", now); got != now.Unix() {
		t.Fatalf("no-ts line must fall back to receipt time")
	}
	if got := parseLineTs("2026/07/28 09:00:00 future line", now); got != now.Unix() {
		t.Fatalf("future line must fall back to receipt time")
	}
	if got := parseLineTs("2026/07/01 09:00:00 stale line", now); got != now.Unix() {
		t.Fatalf("stale line must fall back to receipt time")
	}
}

func TestDowngradeTransportError(t *testing.T) {
	cases := []struct {
		msg  string
		want string
	}{
		{"FastCGI sent in stderr: PHP message: PHP Warning: Undefined array key", "warn"},
		{"FastCGI sent in stderr: PHP message: PHP Deprecated: strpos()", "notice"},
		{"PHP Fatal error: Uncaught Error", "error"},
		{"PHP Warning: x PHP Fatal error: y", "error"},
		{"ts=1 level=warn msg=slow", "warn"},
		{"{\"level\":\"warn\",\"msg\":\"x\"}", "warn"},
		{"2026 [WARN] pool exhausted", "warn"},
		{"FastCGI sent in stderr: \"Primary script unknown\" while reading response header from upstream, client: 203.0.113.30, server: example.com, request: \"GET /byug.php HTTP/1.1\"", "notice"},
		{"access forbidden by rule, client: 203.0.113.30, server: example.com, request: \"GET /www/.git/config HTTP/1.1\"", "notice"},
		{"directory index of \"/www/example.com/www/\" is forbidden, client: 203.0.113.30, server: example.com", "notice"},
		{"plain broken pipe", "error"},
	}
	for _, c := range cases {
		if got := downgradeTransportError("error", c.msg); got != c.want {
			t.Fatalf("msg %q: level %q, want %q", c.msg, got, c.want)
		}
	}
	if got := downgradeTransportError("warn", "level=info x"); got != "warn" {
		t.Fatal("only transport error downgrades")
	}
	if got := downgradeTransportError("warn", "kauditd_printk_skb: 27 callbacks suppressed"); got != "info" {
		t.Fatalf("kernel bookkeeping stays out of the default feed, got %q", got)
	}
	if got := downgradeTransportError("warn", "audit: type=1400 apparmor=\"DENIED\" operation=\"sendmsg\""); got != "warn" {
		t.Fatal("real audit denials keep their level")
	}
}

func TestCollectSkipsForcedBelowMin(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/access.log"
	if err := os.WriteFile(path, []byte("first\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	l := NewLogTailer("nginx/error")
	defer l.CloseFDs()
	now := time.Now()
	lean := protocol.Probe{Type: "logs", Paths: []string{path}, ForceLevel: "info", MinLevel: "notice"}
	if lines, _ := l.Collect("nginx", lean, now); len(lines) != 0 {
		t.Fatalf("lean collect returned %d lines", len(lines))
	}
	if l.seenF[path] {
		t.Fatal("lean collect opened the file")
	}
	if err := os.WriteFile(path, []byte("first\nsecond\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	deep := protocol.Probe{Type: "logs", Paths: []string{path}, ForceLevel: "info", MinLevel: "debug"}
	if lines, _ := l.Collect("nginx", deep, now); len(lines) != 0 {
		t.Fatalf("first deep collect must seed the offset, got %d lines", len(lines))
	}
	if err := os.WriteFile(path, []byte("first\nsecond\nthird\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	lines, _ := l.Collect("nginx", deep, now)
	if len(lines) != 1 || lines[0].Message != "third" {
		t.Fatalf("deep collect got %v", lines)
	}
}

func TestCollectKeepsKubeconfigPathOutOfFileTail(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/rke2.yaml"
	if err := os.WriteFile(path, []byte("server: https://127.0.0.1:6443\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	l := NewLogTailer("k8s/pods")
	defer l.CloseFDs()
	now := time.Now()
	p := protocol.Probe{Type: "logs", K8s: true, Path: path, MinLevel: "debug"}
	l.Collect("k8s", p, now)
	if err := os.WriteFile(path, []byte("server: https://127.0.0.1:6443\ncertificate-authority-data: zzz\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	lines, _ := l.Collect("k8s", p, now.Add(30*time.Second))
	for _, ln := range lines {
		if strings.Contains(ln.Message, "certificate-authority-data") {
			t.Fatal("kubeconfig content leaked into the log feed")
		}
	}
	if l.seenF[path] {
		t.Fatal("k8s probe path must never be tailed as a log file")
	}
}

func TestTailCatchupCapsFloodReads(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/flood.log"
	line := strings.Repeat("x", 99) + "\n"
	if err := os.WriteFile(path, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	l := NewLogTailer("nginx/error")
	defer l.CloseFDs()
	now := time.Now()
	p := protocol.Probe{Type: "logs", Paths: []string{path}, ForceLevel: "error"}
	if _, err := l.Collect("nginx", p, now); err != nil {
		t.Fatal(err)
	}
	big := make([]byte, 12<<20)
	for i := range big {
		big[i] = 'y'
		if i%100 == 99 {
			big[i] = '\n'
		}
	}
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	f.Write(big)
	f.Close()
	lines, err := l.Collect("nginx", p, now.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, ln := range lines {
		total += len(ln.Message)
	}
	if total > tailCatchup+4096 {
		t.Fatalf("catchup read %d bytes, cap is %d", total, tailCatchup)
	}
	st, _ := os.Stat(path)
	if l.offsets[path] != st.Size() {
		t.Fatalf("offset %d, want %d", l.offsets[path], st.Size())
	}
}

func TestFloodBackoffStopsReading(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/flood.log"
	if err := os.WriteFile(path, []byte("seed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	l := NewLogTailer("nginx/error")
	defer l.CloseFDs()
	now := time.Now()
	p := protocol.Probe{Type: "logs", Paths: []string{path}, ForceLevel: "error"}
	l.Collect("nginx", p, now)
	chunk := make([]byte, 5<<20)
	for i := range chunk {
		chunk[i] = 'z'
		if i%100 == 99 {
			chunk[i] = '\n'
		}
	}
	grow := func() {
		f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
		f.Write(chunk)
		f.Close()
	}
	for i := 1; i <= 3; i++ {
		grow()
		now = now.Add(30 * time.Second)
		l.Collect("nginx", p, now)
	}
	if len(l.FloodNotes()) != 1 {
		t.Fatal("flood note expected after the streak")
	}
	grow()
	now = now.Add(30 * time.Second)
	lines, _ := l.Collect("nginx", p, now)
	if len(lines) != 0 {
		t.Fatalf("backoff window must skip reading, got %d lines", len(lines))
	}
	st, _ := os.Stat(path)
	if l.offsets[path] != st.Size() {
		t.Fatal("skip must still jump the offset to the tail")
	}
	grow()
	now = now.Add(6 * time.Minute)
	lines, _ = l.Collect("nginx", p, now)
	if len(lines) == 0 {
		t.Fatal("after the backoff window one capped read must happen")
	}
	if len(l.FloodNotes()) != 0 {
		t.Fatal("the note repeats only after an hour")
	}
}

func TestDirTargetResolvedOncePerTTL(t *testing.T) {
	dir := t.TempDir() + "/w3svc"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/u_ex.log", []byte("seed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	l := NewLogTailer("iis/access")
	defer l.CloseFDs()
	now := time.Now()
	p := protocol.Probe{Type: "logs", Paths: []string{dir}, ForceLevel: "error"}
	if _, err := l.Collect("iis", p, now); err != nil {
		t.Fatal(err)
	}
	first, ok := l.dirF[dir]
	if !ok || first.file != dir+"/u_ex.log" {
		t.Fatalf("dir target not resolved: %+v", l.dirF)
	}
	if _, err := l.Collect("iis", p, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if l.dirF[dir].when != first.when {
		t.Fatal("directory re-listed inside the ttl")
	}
	if _, err := l.Collect("iis", p, now.Add(dirResolveTTL+time.Second)); err != nil {
		t.Fatal(err)
	}
	if !l.dirF[dir].when.After(first.when) {
		t.Fatal("directory must be re-listed once the ttl expires")
	}
}

func TestContentLevelKlog(t *testing.T) {
	cases := []struct {
		msg  string
		want string
	}{
		{"E0726 19:18:59.471992 1 kafka_exporter.go:527] Cannot get current offset", "error"},
		{"W0726 19:18:59.471992 1 reflector.go:100] watch closed", "warn"},
		{"I0726 19:18:59.476334 1 kafka_exporter.go:701] [localhost:9092]", "info"},
		{"F0726 19:18:59.000000 1 main.go:10] boom", "error"},
		{"ts=1 level=error msg=x", "error"},
		{"plain line without markers", ""},
	}
	for _, c := range cases {
		if got := contentLevel(c.msg); got != c.want {
			t.Fatalf("msg %q: level %q, want %q", c.msg, got, c.want)
		}
	}
}

func TestNormalizeLevelPinoNumbers(t *testing.T) {
	cases := map[string]string{
		"50": "error", "60": "error", "40": "warn",
		"30": "info", "20": "debug", "10": "debug",
		"error": "error", "warn": "warn",
	}
	for in, want := range cases {
		if got := normalizeLevel(in); got != want {
			t.Fatalf("normalizeLevel(%q) = %q, want %q", in, got, want)
		}
	}
}
