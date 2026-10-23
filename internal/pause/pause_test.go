package pause

import (
	"os"
	"strings"
	"testing"
)

func TestPauseRoundtrip(t *testing.T) {
	dir := t.TempDir()
	if Read(dir) != "" {
		t.Fatal("no file must read as not paused")
	}
	if err := Write(dir, Unpaid); err != nil {
		t.Fatal(err)
	}
	if Read(dir) != Unpaid {
		t.Fatalf("got %q", Read(dir))
	}
	if err := Write(dir, "something new"); err != nil {
		t.Fatal(err)
	}
	if Read(dir) != Plan {
		t.Fatal("an unknown reason must read as the plan reason")
	}
	if err := Write(dir, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(Path(dir)); !os.IsNotExist(err) {
		t.Fatal("lifting the pause must remove the file")
	}
	if err := Write(dir, ""); err != nil {
		t.Fatal("lifting an absent pause must not fail")
	}
}

func TestPauseMessages(t *testing.T) {
	if Message("") != "" {
		t.Fatal("a monitored host has no message")
	}
	for _, r := range []string{Unpaid, Plan} {
		m := Message(r)
		if !strings.HasPrefix(m, "ERROR: this host is not monitored") {
			t.Fatalf("%s: %q", r, m)
		}
	}
	if Message(Unpaid) == Message(Plan) {
		t.Fatal("the two reasons must read differently")
	}
}
