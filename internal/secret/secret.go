package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"wakora.io/agent/internal/atomicfile"
	"wakora.io/agent/internal/winsec"
)

var localSeed string

func InitSeed(dir string) error {
	path := filepath.Join(dir, ".seed")
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if s := strings.TrimSpace(string(b)); s != "" {
			localSeed = s
			return nil
		}
		return fmt.Errorf("secret: %s is empty - refusing to mint a seed over one that existed, restore the file or re-register the host", path)
	case errors.Is(err, fs.ErrNotExist):
	default:
		return fmt.Errorf("secret: cannot read %s: %w - refusing to mint a seed while the old one may still be there", path, err)
	}
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return fmt.Errorf("secret: no randomness for a new seed: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("secret: cannot create %s: %w", dir, err)
	}
	_ = winsec.ProtectDir(dir)
	s := hex.EncodeToString(raw)
	if err := atomicfile.Write(path, []byte(s), 0o600); err != nil {
		return fmt.Errorf("secret: cannot write %s: %w", path, err)
	}
	localSeed = s
	return nil
}

func machineKey(withSeed bool) []byte {
	material := "wakora-agent-v1:" + MachineID()
	if withSeed && localSeed != "" {
		material += ":" + localSeed
	}
	sum := sha256.Sum256([]byte(material))
	return sum[:]
}

var machineIDOnce sync.Once
var machineID string

func MachineID() string {
	machineIDOnce.Do(func() {
		if id := platformMachineID(); id != "" {
			machineID = id
			return
		}
		if h, err := os.Hostname(); err == nil {
			machineID = h
			return
		}
		machineID = "wakora-fallback"
	})
	return machineID
}

func Encrypt(plain string) (string, error) {
	gcm, err := newGCM(true)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	out := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(out), nil
}

func Decrypt(enc string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(enc))
	if err != nil {
		return "", err
	}
	plain, err := decryptWith(raw, true)
	if err != nil && localSeed != "" {
		return decryptWith(raw, false)
	}
	return plain, err
}

func decryptWith(raw []byte, withSeed bool) (string, error) {
	gcm, err := newGCM(withSeed)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("secret: ciphertext too short")
	}
	nonce, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func newGCM(withSeed bool) (cipher.AEAD, error) {
	block, err := aes.NewCipher(machineKey(withSeed))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
