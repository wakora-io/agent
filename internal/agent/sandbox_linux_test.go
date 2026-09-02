//go:build linux

package agent

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestSandboxRestrictedListsOnlyReadOnlyPaths(t *testing.T) {
	check := func(p string) (bool, bool) {
		switch p {
		case "/var/log":
			return true, true
		case "/tmp":
			return true, true
		case "/var/lib":
			return false, true
		default:
			return false, false
		}
	}
	got := sandboxRestricted([]string{"/var/log", "/tmp", "/var/lib", "/missing"}, check)
	if len(got) != 2 || got[0] != "/var/log" || got[1] != "/tmp" {
		t.Fatalf("want the two read-only paths, got %v", got)
	}
}

func TestSandboxRestrictedIgnoresUnstatablePaths(t *testing.T) {
	check := func(string) (bool, bool) { return true, false }
	if got := sandboxRestricted([]string{"/var/log"}, check); len(got) != 0 {
		t.Fatalf("a failed statfs must not count as restricted, got %v", got)
	}
}

func TestRelaxRecentBlocksARetryInsideTheWindow(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "sandbox-relax")
	now := time.Now()
	if err := os.WriteFile(marker, []byte(strconv.FormatInt(now.Add(-time.Hour).Unix(), 10)), 0o600); err != nil {
		t.Fatal(err)
	}
	if !relaxRecent(marker, now, 6*time.Hour) {
		t.Fatal("an attempt an hour ago must still block a retry")
	}
	if relaxRecent(marker, now.Add(7*time.Hour), 6*time.Hour) {
		t.Fatal("past the window a retry must be allowed again")
	}
}

func TestRelaxRecentAllowsTheFirstAttempt(t *testing.T) {
	if relaxRecent(filepath.Join(t.TempDir(), "absent"), time.Now(), 6*time.Hour) {
		t.Fatal("no marker means no attempt was made yet")
	}
}

func TestRelaxRecentIgnoresGarbageMarker(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "sandbox-relax")
	if err := os.WriteFile(marker, []byte("not a timestamp"), 0o600); err != nil {
		t.Fatal(err)
	}
	if relaxRecent(marker, time.Now(), 6*time.Hour) {
		t.Fatal("an unreadable marker must not block the fix forever")
	}
}
