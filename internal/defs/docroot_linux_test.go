package defs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDocrootMissing(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "index.html")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		root           string
		missing, known bool
	}{
		{dir, false, true},
		{`"` + dir + `"`, false, true},
		{filepath.Join(dir, "gone"), true, true},
		{file, true, true},
		{"/var/www/$host", false, false},
		{"html", false, false},
		{"", false, false},
	} {
		missing, known := docrootMissing(c.root)
		if missing != c.missing || known != c.known {
			t.Fatalf("root %q: missing=%v known=%v, want %v %v", c.root, missing, known, c.missing, c.known)
		}
	}
}
