package secret

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitSeedMintsWhenTheFileIsAbsent(t *testing.T) {
	defer func(prev string) { localSeed = prev }(localSeed)
	dir := t.TempDir()
	if err := InitSeed(dir); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, ".seed"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(b)); len(got) != 64 || got != localSeed {
		t.Fatalf("minted seed %q", got)
	}
}

func TestInitSeedRefusesToReplaceATruncatedSeed(t *testing.T) {
	defer func(prev string) { localSeed = prev }(localSeed)
	dir := t.TempDir()
	path := filepath.Join(dir, ".seed")
	if err := os.WriteFile(path, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := InitSeed(dir); err == nil {
		t.Fatal("an emptied seed file was replaced instead of refused")
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "  \n" {
		t.Fatalf("the file was rewritten: %q %v", string(b), err)
	}
}

func TestInitSeedRefusesWhenTheFileCannotBeRead(t *testing.T) {
	defer func(prev string) { localSeed = prev }(localSeed)
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".seed"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := InitSeed(dir); err == nil {
		t.Fatal("an unreadable seed was replaced instead of refused")
	}
}

func TestInitSeedTakesAnExistingSeedAsFound(t *testing.T) {
	defer func(prev string) { localSeed = prev }(localSeed)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".seed"), []byte("older-format-seed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := InitSeed(dir); err != nil {
		t.Fatal(err)
	}
	if localSeed != "older-format-seed" {
		t.Fatalf("seed = %q", localSeed)
	}
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	enc, err := Encrypt("per-server-key-123")
	if err != nil {
		t.Fatal(err)
	}
	if enc == "per-server-key-123" {
		t.Fatal("not encrypted")
	}
	dec, err := Decrypt(enc)
	if err != nil {
		t.Fatal(err)
	}
	if dec != "per-server-key-123" {
		t.Fatalf("roundtrip: %q", dec)
	}

	enc2, err := Encrypt("per-server-key-123")
	if err != nil {
		t.Fatal(err)
	}
	if enc == enc2 {
		t.Fatal("nonce reuse: identical ciphertexts")
	}
}

func TestDecryptRejectsGarbage(t *testing.T) {
	if _, err := Decrypt("not-base64!!!"); err == nil {
		t.Fatal("garbage decrypted")
	}
	if _, err := Decrypt("QUFBQQ=="); err == nil {
		t.Fatal("short ciphertext decrypted")
	}
}
