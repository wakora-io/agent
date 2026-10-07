package secret

import (
	"encoding/base64"
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

func TestResealMovesALegacyValueOntoTheSeed(t *testing.T) {
	defer func(prev string) { localSeed = prev }(localSeed)
	localSeed = ""
	legacy, err := Encrypt("pre-seed-value")
	if err != nil {
		t.Fatal(err)
	}
	if out, ok := Reseal(legacy); ok || out != legacy {
		t.Fatal("without a seed nothing may be re-sealed")
	}
	localSeed = "seed-for-test"
	out, ok := Reseal(legacy)
	if !ok || out == legacy {
		t.Fatal("a value readable only without the seed was not re-sealed")
	}
	raw, err := base64.StdEncoding.DecodeString(out)
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := decryptWith(raw, true); err != nil || plain != "pre-seed-value" {
		t.Fatalf("re-sealed value does not open with the seed: %q %v", plain, err)
	}
	if again, ok := Reseal(out); ok || again != out {
		t.Fatal("a value already on the seed was re-sealed again")
	}
}

func TestResealStoreRewritesOnlyLegacyFields(t *testing.T) {
	defer func(prev string) { localSeed = prev }(localSeed)
	dir := t.TempDir()
	localSeed = ""
	if err := SetCred(dir, "old", Cred{User: "u", Pass: "p"}); err != nil {
		t.Fatal(err)
	}
	localSeed = "seed-for-test"
	if err := SetCred(dir, "new", Cred{User: "u2", Pass: "p2"}); err != nil {
		t.Fatal(err)
	}
	n, err := ResealStore(dir)
	if err != nil || n != 2 {
		t.Fatalf("want the two legacy fields re-sealed, got %d %v", n, err)
	}
	if n, _ := ResealStore(dir); n != 0 {
		t.Fatalf("second pass re-sealed %d fields", n)
	}
	for name, want := range map[string]string{"old": "p", "new": "p2"} {
		c, ok := GetCred(dir, name)
		if !ok || c.Pass != want {
			t.Fatalf("%s after re-seal: %+v %v", name, c, ok)
		}
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
