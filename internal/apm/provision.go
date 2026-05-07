package apm

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	manifestMaxBytes = 1 << 20
	artifactMaxBytes = 512 << 20
	provisionRetry   = 10 * time.Minute
)

type Provisioner struct {
	baseURL string
	client  *http.Client
	pubKey  string
	dir     string

	mu      sync.Mutex
	active  map[string]bool
	lastErr map[string]string
	lastTry map[string]time.Time

	manMu    sync.Mutex
	manCache []byte
	manAt    time.Time
}

const manifestTTL = 10 * time.Minute

type manifestArtifact struct {
	Name   string `json:"name"`
	File   string `json:"file"`
	Sha256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type signedManifest struct {
	Def json.RawMessage `json:"def"`
	Sig string          `json:"sig"`
}

func NewProvisioner(baseURL string, client *http.Client, pubKey, stateDir string) *Provisioner {
	if baseURL == "" || pubKey == "" {
		return nil
	}
	dl := &http.Client{Timeout: 10 * time.Minute}
	if client != nil {
		dl.Transport = client.Transport
	}
	return &Provisioner{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  dl,
		pubKey:  pubKey,
		dir:     filepath.Join(stateDir, "apm"),
		active:  map[string]bool{},
		lastErr: map[string]string{},
		lastTry: map[string]time.Time{},
	}
}

func (p *Provisioner) Ensure(name string, unpack bool) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active[name] {
		return "provisioning: " + name
	}
	if msg, ok := p.lastErr[name]; ok && time.Since(p.lastTry[name]) < provisionRetry {
		return "provision failed: " + msg
	}
	p.active[name] = true
	p.lastTry[name] = time.Now()
	go func() {
		err := p.fetch(name, unpack)
		p.mu.Lock()
		p.active[name] = false
		if err != nil {
			p.lastErr[name] = err.Error()
			log.Printf("apm provision %s: %v", name, err)
		} else {
			delete(p.lastErr, name)
			log.Printf("apm provision %s: done", name)
		}
		p.mu.Unlock()
	}()
	return "provisioning: " + name
}

func (p *Provisioner) fetch(name string, unpack bool) error {
	art, err := p.lookup(name)
	if err != nil {
		return err
	}
	if art.Size > artifactMaxBytes {
		return fmt.Errorf("artifact %s too large (%d bytes)", name, art.Size)
	}
	if err := os.MkdirAll(p.dir, 0o755); err != nil {
		return err
	}
	tmp := filepath.Join(p.dir, "."+name+".dl")
	if err := p.download("/apm/"+art.File, tmp, art.Sha256); err != nil {
		os.Remove(tmp)
		return err
	}
	if unpack {
		if err := p.unpackFile(name, tmp); err != nil {
			os.Remove(tmp)
			return err
		}
		os.Remove(tmp)
	} else if err := os.Rename(tmp, filepath.Join(p.dir, name)); err != nil {
		return err
	}
	_ = os.WriteFile(p.shaMarker(name), []byte(art.Sha256), 0o644)
	return nil
}

func (p *Provisioner) shaMarker(name string) string {
	return filepath.Join(p.dir, "."+name+".sha")
}

func (p *Provisioner) LocalSha(name string) string {
	b, err := os.ReadFile(p.shaMarker(name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (p *Provisioner) NeedsRefresh(name string) bool {
	art, err := p.lookup(name)
	if err != nil || art.Sha256 == "" {
		return false
	}
	return p.LocalSha(name) != art.Sha256
}

func (p *Provisioner) download(path, dst, wantSha string) error {
	resp, err := p.client.Get(p.baseURL + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", path, resp.Status)
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, artifactMaxBytes))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != wantSha {
		return errors.New("artifact checksum mismatch")
	}
	return nil
}

func (p *Provisioner) manifest() ([]byte, error) {
	p.manMu.Lock()
	defer p.manMu.Unlock()
	if p.manCache != nil && time.Since(p.manAt) < manifestTTL {
		return p.manCache, nil
	}
	raw, err := p.getSmall("/apm/manifest.signed.json")
	if err != nil {
		return nil, err
	}
	p.manCache = raw
	p.manAt = time.Now()
	return raw, nil
}

func (p *Provisioner) lookup(name string) (*manifestArtifact, error) {
	raw, err := p.manifest()
	if err != nil {
		return nil, err
	}
	var sm signedManifest
	if err := json.Unmarshal(raw, &sm); err != nil {
		return nil, errors.New("malformed signed manifest")
	}
	pub, err := base64.StdEncoding.DecodeString(p.pubKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("invalid publisher key")
	}
	sig, err := base64.StdEncoding.DecodeString(sm.Sig)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(pub), sm.Def, sig) {
		return nil, errors.New("manifest signature invalid")
	}
	var m struct {
		Artifacts []manifestArtifact `json:"artifacts"`
	}
	if err := json.Unmarshal(sm.Def, &m); err != nil {
		return nil, errors.New("malformed manifest")
	}
	for i := range m.Artifacts {
		if m.Artifacts[i].Name == name {
			return &m.Artifacts[i], nil
		}
	}
	return nil, fmt.Errorf("artifact %s not in channel manifest", name)
}

func (p *Provisioner) unpackFile(name, archive string) error {
	tmp := filepath.Join(p.dir, ".tmp-"+name)
	if err := os.RemoveAll(tmp); err != nil {
		return err
	}
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		return err
	}
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	err = extractTarGz(f, tmp)
	f.Close()
	if err != nil {
		os.RemoveAll(tmp)
		return err
	}
	dst := filepath.Join(p.dir, name)
	if err := os.RemoveAll(dst); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func extractTarGz(r io.Reader, dst string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		rel := filepath.Clean(hdr.Name)
		if rel == "." || rel == "" {
			continue
		}
		if strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
			return fmt.Errorf("unsafe path in archive: %s", hdr.Name)
		}
		target := filepath.Join(dst, rel)
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			mode := os.FileMode(hdr.Mode & 0o777)
			if mode == 0 {
				mode = 0o644
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if err != nil {
				return err
			}
			_, err = io.Copy(f, io.LimitReader(tr, artifactMaxBytes))
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return err
			}
		}
	}
}

func (p *Provisioner) getSmall(path string) ([]byte, error) {
	resp, err := p.client.Get(p.baseURL + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", path, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, manifestMaxBytes))
}
