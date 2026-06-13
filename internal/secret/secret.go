package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var localSeed string

func InitSeed(dir string) {
	path := filepath.Join(dir, ".seed")
	if b, err := os.ReadFile(path); err == nil {
		if s := strings.TrimSpace(string(b)); s != "" {
			localSeed = s
			return
		}
	}
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return
	}
	s := hex.EncodeToString(raw)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		return
	}
	localSeed = s
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
