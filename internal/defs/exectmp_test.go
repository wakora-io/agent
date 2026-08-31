//go:build !windows

package defs

import (
	"os"
	"strings"
	"testing"
	"time"
)

func resetTmpState() {
	tmpMu.Lock()
	tmpChecked = time.Time{}
	tmpFall = ""
	tmpMu.Unlock()
}

func TestExecEnvLeavesAHealthyHostAlone(t *testing.T) {
	resetTmpState()
	SetExecTmpDir(t.TempDir())
	if env := execEnv(); env != nil {
		t.Fatalf("a writable /tmp got its environment rewritten: %d vars", len(env))
	}
}

func TestExecEnvPointsAtOurOwnDirWhenTmpIsRefused(t *testing.T) {
	resetTmpState()
	own := t.TempDir()
	SetExecTmpDir(own)
	t.Setenv("TMPDIR", "/proc/self/wakora-not-a-dir")
	env := execEnv()
	if env == nil {
		t.Fatal("a refused /tmp produced no fallback")
	}
	found := ""
	for _, v := range env {
		if strings.HasPrefix(v, "TMPDIR=") {
			found = strings.TrimPrefix(v, "TMPDIR=")
		}
	}
	if found != own {
		t.Fatalf("TMPDIR points at %q, expected our own dir", found)
	}
	if _, err := os.Stat(own); err != nil {
		t.Fatalf("the fallback dir was not usable: %v", err)
	}
}

func TestExecEnvWithoutAConfiguredDirStaysOutOfTheWay(t *testing.T) {
	resetTmpState()
	SetExecTmpDir("")
	t.Setenv("TMPDIR", "/proc/self/wakora-not-a-dir")
	if env := execEnv(); env != nil {
		t.Fatal("with nowhere to fall back the environment must be left untouched")
	}
}
