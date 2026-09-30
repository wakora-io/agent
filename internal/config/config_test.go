package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseINI(t *testing.T) {
	in := `
# comment
; also comment
top = 1

[nginx]
log-path = /www/logs
line-without-equals
[mysql]
slow-log = /mysql/slow.log
`
	sections := parseINI(strings.NewReader(in))
	if sections[""]["top"] != "1" {
		t.Fatalf("flat key lost: %v", sections[""])
	}
	if sections["nginx"]["log-path"] != "/www/logs" {
		t.Fatalf("nginx section: %v", sections["nginx"])
	}
	if sections["mysql"]["slow-log"] != "/mysql/slow.log" {
		t.Fatalf("mysql section: %v", sections["mysql"])
	}
}

func TestPendingKeyRoundtrip(t *testing.T) {
	dir := t.TempDir()
	if got := LoadPendingKey(dir); got != "" {
		t.Fatalf("empty dir should have no pending key, got %q", got)
	}
	if err := SavePendingKey(dir, "WK-15-SECRETSECRETSECRETAB"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(PendingKeyPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "WK-15-SECRETSECRETSECRETAB") {
		t.Fatal("pending key stored in plaintext")
	}
	if got := LoadPendingKey(dir); got != "WK-15-SECRETSECRETSECRETAB" {
		t.Fatalf("pending key roundtrip = %q", got)
	}
	ClearPendingKey(dir)
	if got := LoadPendingKey(dir); got != "" {
		t.Fatalf("pending key should be gone, got %q", got)
	}
}

func TestWriteReadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.conf")
	want := map[string]map[string]string{
		"":      {"a": "1"},
		"nginx": {"log-path": "/www", "port": "8080"},
	}
	if err := writeINI(path, want); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got := parseINI(f)
	for section, kv := range want {
		for k, v := range kv {
			if got[section][k] != v {
				t.Fatalf("roundtrip lost %s.%s: got %q want %q", section, k, got[section][k], v)
			}
		}
	}
}

func TestIdentityRoundtrip(t *testing.T) {
	dir := t.TempDir()
	if err := SaveIdentity(dir, "uuid-123", "secret-key"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "identity"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "secret-key") {
		t.Fatal("plaintext key on disk")
	}
	cfg, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerID != "uuid-123" || cfg.Key != "secret-key" {
		t.Fatalf("roundtrip: id=%q key=%q", cfg.ServerID, cfg.Key)
	}
}

func TestSealedIdentityIsSetAside(t *testing.T) {
	dir := t.TempDir()
	if err := writeINI(filepath.Join(dir, "identity"), map[string]map[string]string{"": {"uuid": "uuid-copied", "key": "c2VhbGVkLWVsc2V3aGVyZS1zZWFsZWQtZWxzZXdoZXJl"}}); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(dir)
	if !errors.Is(err, ErrIdentitySealed) {
		t.Fatalf("want ErrIdentitySealed, got %v", err)
	}
	if cfg == nil || cfg.Key != "" {
		t.Fatal("a sealed identity must load as no key")
	}
	moved, err := SetAsideIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(filepath.Base(moved), "identity.undecryptable-") {
		t.Fatalf("unexpected set-aside name %q", moved)
	}
	if _, err := os.Stat(moved); err != nil {
		t.Fatalf("set-aside copy missing: %v", err)
	}
	cfg, err = Load(dir)
	if err != nil || cfg.Key != "" || cfg.ServerID != "" {
		t.Fatalf("after set-aside: err=%v id=%q key=%q", err, cfg.ServerID, cfg.Key)
	}
	if err := SaveIdentity(dir, "uuid-new", "k-new"); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(dir)
	if err != nil || cfg.ServerID != "uuid-new" || cfg.Key != "k-new" {
		t.Fatalf("fresh identity: err=%v id=%q key=%q", err, cfg.ServerID, cfg.Key)
	}
}

func TestIdentityChangedMarker(t *testing.T) {
	dir := t.TempDir()
	if _, ok := TakeIdentityChanged(dir); ok {
		t.Fatal("no marker must read as absent")
	}
	if err := MarkIdentityChanged(dir, "uuid-original"); err != nil {
		t.Fatal(err)
	}
	prev, ok := TakeIdentityChanged(dir)
	if !ok || prev != "uuid-original" {
		t.Fatalf("marker: ok=%v prev=%q", ok, prev)
	}
	if _, ok := TakeIdentityChanged(dir); ok {
		t.Fatal("the marker must be consumed once")
	}
}

func TestCopyRefusalRoundtrip(t *testing.T) {
	dir := t.TempDir()
	if _, ok := LoadCopyRefusal(dir); ok {
		t.Fatal("no refusal must read as absent")
	}
	want := CopyRefusal{Of: "uuid-original", Reason: "plan limit = 3 hosts reached", At: 1700000000}
	if err := SaveCopyRefusal(dir, want); err != nil {
		t.Fatal(err)
	}
	got, ok := LoadCopyRefusal(dir)
	if !ok || got != want {
		t.Fatalf("refusal: ok=%v got=%+v", ok, got)
	}
	ClearCopyRefusal(dir)
	if _, ok := LoadCopyRefusal(dir); ok {
		t.Fatal("refusal must be gone after clear")
	}
}

func TestSaveKeyKeepsUUID(t *testing.T) {
	dir := t.TempDir()
	if err := SaveIdentity(dir, "uuid-1", "k1"); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.SaveKey("k2"); err != nil {
		t.Fatal(err)
	}
	again, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if again.ServerID != "uuid-1" || again.Key != "k2" {
		t.Fatalf("rotate lost identity: id=%q key=%q", again.ServerID, again.Key)
	}
}

func TestBaselineFromConf(t *testing.T) {
	dir := t.TempDir()
	cfg, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Baseline {
		t.Fatal("baseline on without config")
	}
	if err := WriteOverride(dir, "agent", "baseline", "true"); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Baseline {
		t.Fatal("baseline not picked up from wakora.conf")
	}
	if err := WriteOverride(dir, "agent", "baseline", "false"); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Baseline {
		t.Fatal("baseline=false not honored")
	}
}

func TestWriteOverrideMerges(t *testing.T) {
	dir := t.TempDir()
	if err := WriteOverride(dir, "nginx", "log-path", "/www"); err != nil {
		t.Fatal(err)
	}
	if err := WriteOverride(dir, "mysql", "slow-log", "/slow"); err != nil {
		t.Fatal(err)
	}
	if err := WriteOverride(dir, "nginx", "port", "81"); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Overrides["nginx"]["log-path"] != "/www" || cfg.Overrides["nginx"]["port"] != "81" {
		t.Fatalf("nginx overrides: %v", cfg.Overrides["nginx"])
	}
	if cfg.Overrides["mysql"]["slow-log"] != "/slow" {
		t.Fatalf("mysql overrides: %v", cfg.Overrides["mysql"])
	}
}
