package defs

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"wakora.io/agent/internal/protocol"
)

func TestBrokenCounterPatternIsWithheldNotCountedAsEveryLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	if err := os.WriteFile(path, []byte("nothing interesting here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tl := NewTailer([]string{path})
	counters := []protocol.Counter{
		{Name: "svc.broken", Regex: "Invalid user ("},
		{Name: "svc.everything", Regex: ""},
		{Name: "svc.real", Regex: "Invalid user "},
	}
	now := time.Now()
	if _, _, err := tl.Sample(counters, now); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("nothing interesting here\nstill nothing\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pts, _, err := tl.Sample(counters, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, p := range pts {
		got[p.Name] = p.Value
	}
	if _, ok := got["svc.broken"]; ok {
		t.Fatalf("a counter whose pattern does not compile must emit nothing, got %v", got)
	}
	if v, ok := got["svc.everything"]; !ok || v <= 0 {
		t.Fatalf("an EMPTY pattern still means every line by design, got %v", got)
	}
	if v, ok := got["svc.real"]; !ok || v != 0 {
		t.Fatalf("a working pattern with no matches must report zero, got %v", got)
	}
}
