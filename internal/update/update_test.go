package update

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testKey(t *testing.T) (ed25519.PrivateKey, string) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, base64.StdEncoding.EncodeToString(pub)
}

func assetKey() string {
	a, _ := assetNames()
	return strings.TrimPrefix(a, "/")
}

func manifestServer(priv ed25519.PrivateKey, version string, issuedAt int64, bin []byte, tamperSig bool) *httptest.Server {
	name := assetKey()
	sum := sha256.Sum256(bin)
	mf := manifest{Version: version, IssuedAt: issuedAt, Assets: map[string]string{name: hex.EncodeToString(sum[:])}}
	mfBytes, _ := json.Marshal(mf)
	signed := mfBytes
	if tamperSig {
		signed = append(append([]byte{}, mfBytes...), 'x')
	}
	mfSig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, signed))
	binSig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, bin))
	mux := http.NewServeMux()
	mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) { w.Write(mfBytes) })
	mux.HandleFunc("/manifest.json.sig", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, mfSig) })
	mux.HandleFunc("/"+name, func(w http.ResponseWriter, r *http.Request) { w.Write(bin) })
	mux.HandleFunc("/"+name+".sig", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, binSig) })
	return httptest.NewServer(mux)
}

func TestManifestVerifyAndApply(t *testing.T) {
	priv, pub := testKey(t)
	bin := []byte("fake wakora binary r219")
	srv := manifestServer(priv, "r219", 1000, bin, false)
	defer srv.Close()

	u := New(srv.URL, nil, pub, filepath.Join(t.TempDir(), "update-manifest"))
	v, err := u.LatestVersion()
	if err != nil || v != "r219" {
		t.Fatalf("LatestVersion=%q err=%v", v, err)
	}
	if u.lastIssuedAt() != 1000 {
		t.Fatalf("issuedAt not persisted: %d", u.lastIssuedAt())
	}
	target := filepath.Join(t.TempDir(), "wakora")
	if err := u.Apply(target); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	got, _ := os.ReadFile(target)
	if string(got) != string(bin) {
		t.Fatalf("applied binary mismatch: %q", got)
	}
}

func TestManifestRollbackRefused(t *testing.T) {
	priv, pub := testKey(t)
	state := filepath.Join(t.TempDir(), "update-manifest")

	srvNew := manifestServer(priv, "r219", 2000, []byte("bin219"), false)
	u := New(srvNew.URL, nil, pub, state)
	if _, err := u.LatestVersion(); err != nil {
		t.Fatal(err)
	}
	srvNew.Close()

	srvOld := manifestServer(priv, "r210", 1000, []byte("bin210"), false)
	defer srvOld.Close()
	u2 := New(srvOld.URL, nil, pub, state)
	if _, err := u2.LatestVersion(); err == nil {
		t.Fatal("older issuedAt manifest must be refused as a rollback")
	}
}

func TestManifestBadSignatureRejected(t *testing.T) {
	priv, pub := testKey(t)
	srv := manifestServer(priv, "r219", 1000, []byte("bin"), true)
	defer srv.Close()

	u := New(srv.URL, nil, pub, filepath.Join(t.TempDir(), "s"))
	if _, err := u.LatestVersion(); err == nil {
		t.Fatal("tampered manifest signature must be rejected")
	}
}

func TestManifestWrongKeyRejected(t *testing.T) {
	priv, _ := testKey(t)
	_, otherPub := testKey(t)
	srv := manifestServer(priv, "r219", 1000, []byte("bin"), false)
	defer srv.Close()

	u := New(srv.URL, nil, otherPub, filepath.Join(t.TempDir(), "s"))
	if _, err := u.LatestVersion(); err == nil {
		t.Fatal("manifest signed by a different key must be rejected")
	}
}

func TestNoPubKeyFailsClosed(t *testing.T) {
	priv, _ := testKey(t)
	srv := manifestServer(priv, "r219", 1000, []byte("bin"), false)
	defer srv.Close()

	u := New(srv.URL, nil, "", filepath.Join(t.TempDir(), "s"))
	if _, err := u.LatestVersion(); err == nil {
		t.Fatal("empty publisher key must fail closed")
	}
}

func TestApplyChecksumMismatch(t *testing.T) {
	priv, pub := testKey(t)
	bin := []byte("real binary")
	name := assetKey()
	sum := sha256.Sum256([]byte("a different binary"))
	mf := manifest{Version: "r219", IssuedAt: 1000, Assets: map[string]string{name: hex.EncodeToString(sum[:])}}
	mfBytes, _ := json.Marshal(mf)
	mfSig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, mfBytes))
	binSig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, bin))
	mux := http.NewServeMux()
	mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) { w.Write(mfBytes) })
	mux.HandleFunc("/manifest.json.sig", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, mfSig) })
	mux.HandleFunc("/"+name, func(w http.ResponseWriter, r *http.Request) { w.Write(bin) })
	mux.HandleFunc("/"+name+".sig", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, binSig) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	u := New(srv.URL, nil, pub, filepath.Join(t.TempDir(), "s"))
	if _, err := u.LatestVersion(); err != nil {
		t.Fatal(err)
	}
	if err := u.Apply(filepath.Join(t.TempDir(), "wakora")); err == nil {
		t.Fatal("binary whose sha does not match the signed manifest must be rejected")
	}
}

func versionedServer(priv ed25519.PrivateKey, version string, issuedAt int64, bin []byte) *httptest.Server {
	name := assetKey()
	sum := sha256.Sum256(bin)
	mf := manifest{Version: version, IssuedAt: issuedAt, Assets: map[string]string{name: hex.EncodeToString(sum[:])}}
	mfBytes, _ := json.Marshal(mf)
	mfSig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, mfBytes))
	binSig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, bin))
	p := "/" + version
	mux := http.NewServeMux()
	mux.HandleFunc(p+"/manifest.json", func(w http.ResponseWriter, r *http.Request) { w.Write(mfBytes) })
	mux.HandleFunc(p+"/manifest.json.sig", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, mfSig) })
	mux.HandleFunc(p+"/"+name, func(w http.ResponseWriter, r *http.Request) { w.Write(bin) })
	mux.HandleFunc(p+"/"+name+".sig", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, binSig) })
	return httptest.NewServer(mux)
}

func TestApplyPinnedVersion(t *testing.T) {
	priv, pub := testKey(t)
	bin := []byte("wakora r227 pinned build")
	srv := versionedServer(priv, "r227", 500, bin)
	defer srv.Close()

	u := New(srv.URL, nil, pub, filepath.Join(t.TempDir(), "s"))
	mf, err := u.PinnedManifest("r227")
	if err != nil || mf.Version != "r227" {
		t.Fatalf("PinnedManifest err=%v mf=%+v", err, mf)
	}
	target := filepath.Join(t.TempDir(), "wakora")
	if err := u.ApplyPinned(target, "r227"); err != nil {
		t.Fatalf("ApplyPinned: %v", err)
	}
	got, _ := os.ReadFile(target)
	if string(got) != string(bin) {
		t.Fatalf("pinned binary mismatch: %q", got)
	}
}

func TestApplyPinnedBelowFloorRefused(t *testing.T) {
	_, pub := testKey(t)
	u := New("http://127.0.0.1:1", nil, pub, filepath.Join(t.TempDir(), "s"))
	if err := u.ApplyPinned(filepath.Join(t.TempDir(), "wakora"), "r220"); err == nil {
		t.Fatal("a pin below the pin-aware floor must be refused before any fetch")
	}
}

func TestPinSupported(t *testing.T) {
	cases := []struct {
		v    string
		want bool
	}{
		{"r220", false},
		{"r221", true},
		{"r245", true},
		{"dev", false},
		{"", false},
		{"garbage", false},
	}
	for _, c := range cases {
		if got := PinSupported(c.v); got != c.want {
			t.Errorf("PinSupported(%q)=%v want %v", c.v, got, c.want)
		}
	}
}

func TestPinnedManifestVersionMismatchRejected(t *testing.T) {
	priv, pub := testKey(t)
	srv := versionedServer(priv, "r217", 500, []byte("x"))
	defer srv.Close()

	u := New(srv.URL, nil, pub, filepath.Join(t.TempDir(), "s"))
	if _, err := u.PinnedManifest("r218"); err == nil {
		t.Fatal("a manifest whose version != requested path must be rejected")
	}
}

func TestPinnedBypassesMonotonicGuard(t *testing.T) {
	priv, pub := testKey(t)
	state := filepath.Join(t.TempDir(), "s")

	latest := manifestServer(priv, "r220", 9000, []byte("latest"), false)
	u := New(latest.URL, nil, pub, state)
	if _, err := u.LatestVersion(); err != nil {
		t.Fatal(err)
	}
	latest.Close()

	old := versionedServer(priv, "r210", 100, []byte("old"))
	defer old.Close()
	u2 := New(old.URL, nil, pub, state)
	if _, err := u2.PinnedManifest("r210"); err != nil {
		t.Fatalf("an explicit pin to an older version must bypass the monotonic rollback guard: %v", err)
	}
}

func TestNewer(t *testing.T) {
	cases := []struct {
		latest, current string
		want            bool
	}{
		{"r119", "r118", true},
		{"r118", "r118", false},
		{"r117", "r118", false},
		{"r200", "r99", true},
		{"r5", "dev", true},
		{"garbage", "r10", false},
		{"r10", "garbage", true},
	}
	for _, c := range cases {
		if got := Newer(c.latest, c.current); got != c.want {
			t.Errorf("Newer(%q,%q)=%v want %v", c.latest, c.current, got, c.want)
		}
	}
}
