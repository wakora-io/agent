package secret

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCredRoundtrip(t *testing.T) {
	dir := t.TempDir()
	if err := SetCred(dir, "mysql-monitor", Cred{User: "mon", Pass: "p@ss w0rd"}); err != nil {
		t.Fatal(err)
	}
	got, ok := GetCred(dir, "mysql-monitor")
	if !ok || got.User != "mon" || got.Pass != "p@ss w0rd" {
		t.Fatalf("roundtrip: %+v ok=%v", got, ok)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "secrets.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "p@ss w0rd") || strings.Contains(string(raw), "mon\n") {
		t.Fatal("plaintext credential on disk")
	}
}

func TestListAndRemove(t *testing.T) {
	dir := t.TempDir()
	_ = SetCred(dir, "b-svc", Cred{User: "u", Pass: "p"})
	_ = SetCred(dir, "a-svc", Cred{User: "u", Pass: "p"})
	names := ListCreds(dir)
	if len(names) != 2 || names[0] != "a-svc" || names[1] != "b-svc" {
		t.Fatalf("list not sorted: %v", names)
	}
	removed, err := RemoveCred(dir, "a-svc")
	if err != nil || !removed {
		t.Fatalf("remove: %v %v", removed, err)
	}
	if _, ok := GetCred(dir, "a-svc"); ok {
		t.Fatal("removed cred still present")
	}
	if _, ok := GetCred(dir, "b-svc"); !ok {
		t.Fatal("sibling cred lost on remove")
	}
	if removed, _ := RemoveCred(dir, "missing"); removed {
		t.Fatal("removed nonexistent")
	}
}

func TestMissingCred(t *testing.T) {
	if _, ok := GetCred(t.TempDir(), "nope"); ok {
		t.Fatal("missing cred reported present")
	}
}
