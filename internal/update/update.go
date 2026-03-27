package update

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Updater struct {
	baseURL string
	client  *http.Client
	pubKey  string
}

func New(baseURL string, client *http.Client, pubKey string) *Updater {
	c := &http.Client{Timeout: 10 * time.Minute}
	if client != nil {
		c.Transport = client.Transport
	}
	return &Updater{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  c,
		pubKey:  pubKey,
	}
}

func revNum(v string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimPrefix(v, "r"))
	if err != nil {
		return 0, false
	}
	return n, true
}

func Newer(latest, current string) bool {
	ln, lok := revNum(latest)
	if !lok {
		return false
	}
	cn, cok := revNum(current)
	if !cok {
		return true
	}
	return ln > cn
}

func (u *Updater) LatestVersion() (string, error) {
	body, err := u.get("/version")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

func (u *Updater) Apply(target string) error {
	asset, sumAsset := assetNames()
	sumBody, err := u.get(sumAsset)
	if err != nil {
		return err
	}
	fields := strings.Fields(string(sumBody))
	if len(fields) == 0 {
		return errors.New("update: empty checksum")
	}
	bin, err := u.get(asset)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(bin)
	if hex.EncodeToString(sum[:]) != fields[0] {
		return errors.New("update: checksum mismatch")
	}
	if err := u.verifySignature(asset, bin); err != nil {
		return err
	}

	dir := filepath.Dir(target)
	tmp, err := os.CreateTemp(dir, ".wakora-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(bin); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Chmod(name, 0o755); err != nil {
		os.Remove(name)
		return err
	}
	if err := replaceBinary(name, target); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

func (u *Updater) verifySignature(asset string, bin []byte) error {
	if u.pubKey == "" {
		return errors.New("update: no publisher key built in, refusing unsigned binary")
	}
	pub, err := base64.StdEncoding.DecodeString(u.pubKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("update: invalid publisher key")
	}
	sigBody, err := u.get(asset + ".sig")
	if err != nil {
		return fmt.Errorf("update: signature unavailable: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigBody)))
	if err != nil {
		return errors.New("update: malformed signature")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), bin, sig) {
		return errors.New("update: binary signature invalid")
	}
	return nil
}

func (u *Updater) get(path string) ([]byte, error) {
	resp, err := u.client.Get(u.baseURL + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("update: GET %s: %s", path, resp.Status)
	}
	return io.ReadAll(resp.Body)
}
