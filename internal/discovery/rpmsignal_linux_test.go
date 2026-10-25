package discovery

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRpmSignalFollowsTheDatabaseFileNotTheDirectory(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "rpmdb.sqlite")
	if err := os.WriteFile(db, []byte("first"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := os.Chtimes(db, old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(dir, old, old); err != nil {
		t.Fatal(err)
	}
	before := rpmSignal(dir)
	if before == "" {
		t.Fatal("no signal for an existing database file")
	}

	f, err := os.OpenFile(db, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("second package set"), 0); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := os.Chtimes(dir, old, old); err != nil {
		t.Fatal(err)
	}

	if after := rpmSignal(dir); after == before {
		t.Fatalf("an in-place database rewrite left the signal unchanged: %q", after)
	}
}

func TestRpmSignalIsEmptyWithoutADatabase(t *testing.T) {
	if s := rpmSignal(t.TempDir()); s != "" {
		t.Fatalf("signal %q for a directory without a database", s)
	}
}
