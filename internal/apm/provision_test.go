package apm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func tarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func channelServer(t *testing.T, priv ed25519.PrivateKey, files map[string][]byte) *httptest.Server {
	t.Helper()
	arts := []manifestArtifact{}
	for f, data := range files {
		sum := sha256.Sum256(data)
		name := f
		if n, ok := trimTarGz(f); ok {
			name = n
		}
		arts = append(arts, manifestArtifact{Name: name, File: f, Sha256: hex.EncodeToString(sum[:]), Size: int64(len(data))})
	}
	def, _ := json.Marshal(map[string]any{"artifacts": arts})
	signed, _ := json.Marshal(signedManifest{Def: def, Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, def))})
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/apm/manifest.signed.json" {
			w.Write(signed)
			return
		}
		for f, data := range files {
			if r.URL.Path == "/apm/"+f {
				w.Write(data)
				return
			}
		}
		http.NotFound(w, r)
	}))
}

func trimTarGz(f string) (string, bool) {
	if len(f) > 7 && f[len(f)-7:] == ".tar.gz" {
		return f[:len(f)-7], true
	}
	return f, false
}

func waitProvision(t *testing.T, p *Provisioner, name string, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		active := p.active[name]
		msg := p.lastErr[name]
		p.mu.Unlock()
		if !active {
			if want == "" && msg == "" {
				return
			}
			if want != "" && msg != "" {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("provision %s did not settle", name)
}

func TestProvisionBundleUnpack(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bundle := tarGz(t, map[string]string{"net/hook.dll": "hook", "win-x64/native.dll": "native"})
	srv := channelServer(t, priv, map[string][]byte{"opentelemetry-dotnet-windows-amd64.tar.gz": bundle})
	defer srv.Close()

	state := t.TempDir()
	p := NewProvisioner(srv.URL, srv.Client(), base64.StdEncoding.EncodeToString(pub), state)
	msg := p.Ensure("opentelemetry-dotnet-windows-amd64", true)
	if msg != "provisioning: opentelemetry-dotnet-windows-amd64" {
		t.Fatalf("unexpected state: %s", msg)
	}
	waitProvision(t, p, "opentelemetry-dotnet-windows-amd64", "")
	data, err := os.ReadFile(filepath.Join(state, "apm", "opentelemetry-dotnet-windows-amd64", "win-x64", "native.dll"))
	if err != nil || string(data) != "native" {
		t.Fatalf("bundle not unpacked: %v", err)
	}
}

func TestProvisionSingleFile(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	so := []byte("elf-bytes")
	srv := channelServer(t, priv, map[string][]byte{"opentelemetry-8.3-nts-amd64-glibc.so": so})
	defer srv.Close()

	state := t.TempDir()
	p := NewProvisioner(srv.URL, srv.Client(), base64.StdEncoding.EncodeToString(pub), state)
	p.Ensure("opentelemetry-8.3-nts-amd64-glibc.so", false)
	waitProvision(t, p, "opentelemetry-8.3-nts-amd64-glibc.so", "")
	data, err := os.ReadFile(filepath.Join(state, "apm", "opentelemetry-8.3-nts-amd64-glibc.so"))
	if err != nil || string(data) != "elf-bytes" {
		t.Fatalf("artifact not placed: %v", err)
	}
}

func TestProvisionRejectsBadSignature(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	srv := channelServer(t, otherPriv, map[string][]byte{"x.so": []byte("x")})
	defer srv.Close()

	p := NewProvisioner(srv.URL, srv.Client(), base64.StdEncoding.EncodeToString(pub), t.TempDir())
	p.Ensure("x.so", false)
	waitProvision(t, p, "x.so", "err")
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.lastErr["x.so"] != "manifest signature invalid" {
		t.Fatalf("expected signature rejection, got %q", p.lastErr["x.so"])
	}
}

func TestProvisionRejectsChecksumMismatch(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	files := map[string][]byte{"y.so": []byte("real")}
	arts := []manifestArtifact{{Name: "y.so", File: "y.so", Sha256: hex.EncodeToString(bytes.Repeat([]byte{1}, 32)), Size: 4}}
	def, _ := json.Marshal(map[string]any{"artifacts": arts})
	signed, _ := json.Marshal(signedManifest{Def: def, Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, def))})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/apm/manifest.signed.json" {
			w.Write(signed)
			return
		}
		w.Write(files["y.so"])
	}))
	defer srv.Close()

	state := t.TempDir()
	p := NewProvisioner(srv.URL, srv.Client(), base64.StdEncoding.EncodeToString(pub), state)
	p.Ensure("y.so", false)
	waitProvision(t, p, "y.so", "err")
	p.mu.Lock()
	msg := p.lastErr["y.so"]
	p.mu.Unlock()
	if msg != "artifact checksum mismatch" {
		t.Fatalf("expected checksum rejection, got %q", msg)
	}
	if _, err := os.Stat(filepath.Join(state, "apm", "y.so")); err == nil {
		t.Fatal("corrupt artifact must not be placed")
	}
}

func TestExtractRejectsTraversal(t *testing.T) {
	evil := tarGz(t, map[string]string{"../escape": "boom"})
	if err := extractTarGz(bytes.NewReader(evil), t.TempDir()); err == nil {
		t.Fatal("path traversal accepted")
	}
}
