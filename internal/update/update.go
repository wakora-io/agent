package update

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Updater struct {
	baseURL string
	client  *http.Client
}

func New(baseURL string, client *http.Client) *Updater {
	c := &http.Client{Timeout: time.Minute}
	if client != nil {
		c.Transport = client.Transport
	}
	return &Updater{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  c,
	}
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
