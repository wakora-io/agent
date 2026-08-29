package defs

import (
	"os"
	"strings"
	"testing"
	"time"

	"wakora.io/agent/internal/protocol"
)

func collectLines(t *testing.T, l *LogTailer, path string, now time.Time) []protocol.LogLine {
	t.Helper()
	p := protocol.Probe{Type: "logs", Paths: []string{path}, ForceLevel: "error"}
	out, err := l.Collect("nginx", p, now)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestTailFdCacheHoldsAcrossCycles(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/error.log"
	if err := os.WriteFile(path, []byte("seed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	l := NewLogTailer("nginx/error")
	defer l.CloseFDs()
	now := time.Now()
	collectLines(t, l, path, now)
	if !l.fds.has(path) {
		t.Fatal("file not cached after first collect")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("grown line\n")
	f.Close()
	out := collectLines(t, l, path, now)
	if len(out) != 1 || !strings.Contains(out[0].Message, "grown line") {
		t.Fatalf("cached fd missed growth: %+v", out)
	}
}

func TestTailFdRotationRenameCreate(t *testing.T) {
	oldN := rotCheckN
	rotCheckN = 1
	defer func() { rotCheckN = oldN }()
	dir := t.TempDir()
	path := dir + "/error.log"
	if err := os.WriteFile(path, []byte("seed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	l := NewLogTailer("nginx/error")
	defer l.CloseFDs()
	now := time.Now()
	collectLines(t, l, path, now)
	collectLines(t, l, path, now)
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("fresh after rotate\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := collectLines(t, l, path, now)
	if len(out) != 1 || !strings.Contains(out[0].Message, "fresh after rotate") {
		t.Fatalf("rotated file not picked up: %+v", out)
	}
}

func TestTailFdGoneClosesEntry(t *testing.T) {
	oldN := rotCheckN
	rotCheckN = 1
	defer func() { rotCheckN = oldN }()
	dir := t.TempDir()
	path := dir + "/error.log"
	if err := os.WriteFile(path, []byte("seed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	l := NewLogTailer("nginx/error")
	defer l.CloseFDs()
	now := time.Now()
	collectLines(t, l, path, now)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	p := protocol.Probe{Type: "logs", Paths: []string{path}, ForceLevel: "error"}
	if _, err := l.Collect("nginx", p, now); err == nil {
		t.Fatal("expected error for removed file")
	}
	if l.fds.has(path) {
		t.Fatal("removed file still cached")
	}
}

func TestTailFdSweepDropsStalePaths(t *testing.T) {
	dir := t.TempDir()
	a := dir + "/a.log"
	b := dir + "/b.log"
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, []byte("seed\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	l := NewLogTailer("nginx/error")
	defer l.CloseFDs()
	now := time.Now()
	p := protocol.Probe{Type: "logs", Paths: []string{a, b}, ForceLevel: "error"}
	if _, err := l.Collect("nginx", p, now); err != nil {
		t.Fatal(err)
	}
	if !l.fds.has(a) || !l.fds.has(b) {
		t.Fatal("both files should be cached")
	}
	p.Paths = []string{a}
	if _, err := l.Collect("nginx", p, now); err != nil {
		t.Fatal(err)
	}
	if !l.fds.has(a) || l.fds.has(b) {
		t.Fatal("sweep should keep a and drop b")
	}
}

func TestTailFdCapFallsBack(t *testing.T) {
	oldCap := fdCacheCap
	fdCacheCap = 1
	defer func() { fdCacheCap = oldCap }()
	dir := t.TempDir()
	a := dir + "/a.log"
	b := dir + "/b.log"
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, []byte("seed\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	l := NewLogTailer("nginx/error")
	defer l.CloseFDs()
	now := time.Now()
	p := protocol.Probe{Type: "logs", Paths: []string{a, b}, ForceLevel: "error"}
	if _, err := l.Collect("nginx", p, now); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{a, b} {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		f.WriteString("line two\n")
		f.Close()
	}
	out, err := l.Collect("nginx", p, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("expected both files read past the cap, got %d", len(out))
	}
	if len(l.fds.m) != 1 {
		t.Fatalf("cache should hold exactly cap entries, got %d", len(l.fds.m))
	}
}

func TestTailFdCopytruncateReadsFromZero(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/error.log"
	if err := os.WriteFile(path, []byte("a long seed line to move the offset forward\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	l := NewLogTailer("nginx/error")
	defer l.CloseFDs()
	now := time.Now()
	collectLines(t, l, path, now)
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("tiny\n")
	f.Close()
	out := collectLines(t, l, path, now)
	if len(out) != 1 || !strings.Contains(out[0].Message, "tiny") {
		t.Fatalf("copytruncate not read from zero: %+v", out)
	}
}

func TestTailerFdRotation(t *testing.T) {
	oldN := rotCheckN
	rotCheckN = 1
	defer func() { rotCheckN = oldN }()
	dir := t.TempDir()
	path := dir + "/access.log"
	if err := os.WriteFile(path, []byte("seed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tl := NewTailer([]string{path})
	defer tl.CloseFDs()
	counters := []protocol.Counter{{Name: "svc.nginx.req_rate", Regex: ""}}
	now := time.Now()
	if _, _, err := tl.Sample(counters, now); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("r1\nr2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pts, _, err := tl.Sample(counters, now.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(pts) != 1 || pts[0].Value < 0.06 {
		t.Fatalf("rotated access log lines not counted: %+v", pts)
	}
	tl.CloseFDs()
	if len(tl.fds.m) != 0 {
		t.Fatal("CloseFDs left entries behind")
	}
}
