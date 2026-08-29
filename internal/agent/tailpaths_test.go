package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPickTailPathsFactWins(t *testing.T) {
	got := pickTailPaths([]string{"/from/fact"}, []string{"/cand/a"}, "/legacy")
	if len(got) != 1 || got[0] != "/from/fact" {
		t.Fatalf("got %v", got)
	}
}

func TestPickTailPathsExistingCandidate(t *testing.T) {
	dir := t.TempDir()
	have := filepath.Join(dir, "mail.log")
	if err := os.WriteFile(have, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "maillog")
	got := pickTailPaths(nil, []string{missing, have}, "")
	if len(got) != 1 || got[0] != have {
		t.Fatalf("got %v", got)
	}
}

func TestPickTailPathsNoCandidateExists(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	got := pickTailPaths(nil, []string{a, b}, "")
	if len(got) != 2 || got[0] != a || got[1] != b {
		t.Fatalf("got %v", got)
	}
}

func TestPickTailPathsLegacyPath(t *testing.T) {
	got := pickTailPaths(nil, nil, "/var/log/mail.log")
	if len(got) != 1 || got[0] != "/var/log/mail.log" {
		t.Fatalf("got %v", got)
	}
}

func TestPickTailPathsEmpty(t *testing.T) {
	if got := pickTailPaths(nil, nil, ""); got != nil {
		t.Fatalf("got %v", got)
	}
}
