package update

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"wakora.io/agent/internal/atomicfile"
)

type Updater struct {
	baseURL   string
	client    *http.Client
	pubKey    string
	statePath string

	mu     sync.Mutex
	cached *manifest
}

type manifest struct {
	Version  string            `json:"version"`
	IssuedAt int64             `json:"issuedAt"`
	Assets   map[string]string `json:"assets"`
}

func New(baseURL string, client *http.Client, pubKey, statePath string) *Updater {
	c := &http.Client{Timeout: 10 * time.Minute}
	if client != nil {
		c.Transport = client.Transport
	}
	return &Updater{
		baseURL:   strings.TrimRight(baseURL, "/"),
		client:    c,
		pubKey:    pubKey,
		statePath: statePath,
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
	mf, err := u.fetchManifest()
	if err != nil {
		return "", err
	}
	u.mu.Lock()
	u.cached = mf
	u.mu.Unlock()
	return mf.Version, nil
}

func (u *Updater) Apply(target string) error {
	u.mu.Lock()
	mf := u.cached
	u.mu.Unlock()
	if mf == nil {
		var err error
		mf, err = u.fetchManifest()
		if err != nil {
			return err
		}
	}
	return u.applyManifest(target, mf, "")
}

func (u *Updater) ApplyPinned(target, version string) error {
	mf, err := u.PinnedManifest(version)
	if err != nil {
		return err
	}
	return u.applyManifest(target, mf, "/"+version)
}

func (u *Updater) applyManifest(target string, mf *manifest, dirPrefix string) error {
	asset, _ := assetNames()
	name := strings.TrimPrefix(asset, "/")
	wantSha, ok := mf.Assets[name]
	if !ok || wantSha == "" {
		return fmt.Errorf("update: asset %s absent from the signed manifest", name)
	}
	bin, err := u.get(dirPrefix + asset)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(bin)
	if hex.EncodeToString(sum[:]) != wantSha {
		return errors.New("update: checksum mismatch against signed manifest")
	}
	if err := u.verifyBinarySig(dirPrefix+asset, bin); err != nil {
		return err
	}

	dir := filepath.Dir(target)
	tmp, err := os.CreateTemp(dir, ".wakora-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(bin); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(tmpName, 0o755); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := replaceBinary(tmpName, target); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}

func (u *Updater) fetchManifest() (*manifest, error) {
	return u.manifestAt("/manifest.json", "", true)
}

func (u *Updater) PinnedManifest(version string) (*manifest, error) {
	return u.manifestAt("/"+version+"/manifest.json", version, false)
}

func (u *Updater) manifestAt(path, wantVersion string, monotonic bool) (*manifest, error) {
	body, err := u.get(path)
	if err != nil {
		return nil, err
	}
	sigBody, err := u.get(path + ".sig")
	if err != nil {
		return nil, fmt.Errorf("update: manifest signature unavailable: %w", err)
	}
	if err := u.verifyBlob(body, sigBody); err != nil {
		return nil, err
	}
	var mf manifest
	if err := json.Unmarshal(body, &mf); err != nil {
		return nil, fmt.Errorf("update: manifest parse: %w", err)
	}
	if mf.Version == "" || len(mf.Assets) == 0 {
		return nil, errors.New("update: manifest incomplete")
	}
	if wantVersion != "" && mf.Version != wantVersion {
		return nil, fmt.Errorf("update: manifest at %s declares %s, expected %s", path, mf.Version, wantVersion)
	}
	if monotonic {
		if last := u.lastIssuedAt(); mf.IssuedAt < last {
			return nil, fmt.Errorf("update: manifest issuedAt %d older than last seen %d, refusing rollback", mf.IssuedAt, last)
		}
		u.storeIssuedAt(mf.IssuedAt)
	}
	return &mf, nil
}

func (u *Updater) verifyBinarySig(asset string, bin []byte) error {
	sigBody, err := u.get(asset + ".sig")
	if err != nil {
		return fmt.Errorf("update: binary signature unavailable: %w", err)
	}
	return u.verifyBlob(bin, sigBody)
}

func (u *Updater) verifyBlob(data, sigBody []byte) error {
	if u.pubKey == "" {
		return errors.New("update: no publisher key built in, refusing unverified content")
	}
	pub, err := base64.StdEncoding.DecodeString(u.pubKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("update: invalid publisher key")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigBody)))
	if err != nil {
		return errors.New("update: malformed signature")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), data, sig) {
		return errors.New("update: signature invalid")
	}
	return nil
}

func (u *Updater) lastIssuedAt() int64 {
	if u.statePath == "" {
		return 0
	}
	b, err := os.ReadFile(u.statePath)
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return n
}

func (u *Updater) storeIssuedAt(ts int64) {
	if u.statePath == "" || ts <= u.lastIssuedAt() {
		return
	}
	_ = atomicfile.Write(u.statePath, []byte(strconv.FormatInt(ts, 10)), 0o600)
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
