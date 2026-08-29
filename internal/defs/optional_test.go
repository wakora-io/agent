package defs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAnyPathExists(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "mail.log")
	if err := os.WriteFile(real, []byte("x\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if AnyPathExists([]string{filepath.Join(dir, "absent.log")}) {
		t.Fatal("absent path reported as existing")
	}
	if !AnyPathExists([]string{filepath.Join(dir, "absent.log"), real}) {
		t.Fatal("existing path not found")
	}
}
