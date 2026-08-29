package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func selfSignedCert(t *testing.T, cn string) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der, key
}

func pinOf(t *testing.T, der []byte) string {
	t.Helper()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

func tlsServer(t *testing.T, chain [][]byte, key *ecdsa.PrivateKey) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestPinnedClientAcceptsPinnedLeaf(t *testing.T) {
	der, key := selfSignedCert(t, "eu.gw.wakora.io")
	srv := tlsServer(t, [][]byte{der}, key)
	resp, err := PinnedClient(pinOf(t, der)).Get(srv.URL)
	if err != nil {
		t.Fatalf("pinned leaf was rejected: %v", err)
	}
	resp.Body.Close()
}

func TestPinnedClientRejectsForeignLeafWithPinnedCertInChain(t *testing.T) {
	realDER, _ := selfSignedCert(t, "eu.gw.wakora.io")
	foreignDER, foreignKey := selfSignedCert(t, "attacker")
	srv := tlsServer(t, [][]byte{foreignDER, realDER}, foreignKey)
	resp, err := PinnedClient(pinOf(t, realDER)).Get(srv.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("pin accepted a foreign leaf carrying the pinned certificate later in the chain")
	}
}

func TestPinnedClientRejectsForeignLeaf(t *testing.T) {
	realDER, _ := selfSignedCert(t, "eu.gw.wakora.io")
	foreignDER, foreignKey := selfSignedCert(t, "attacker")
	srv := tlsServer(t, [][]byte{foreignDER}, foreignKey)
	resp, err := PinnedClient(pinOf(t, realDER)).Get(srv.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("pin accepted an unrelated certificate")
	}
}

func TestDecodePin(t *testing.T) {
	good := base64.StdEncoding.EncodeToString(make([]byte, sha256.Size))
	if _, err := decodePin(good); err != nil {
		t.Fatalf("valid pin rejected: %v", err)
	}
	if _, err := decodePin("  " + good + "\n"); err != nil {
		t.Fatalf("whitespace-padded pin rejected: %v", err)
	}
	for _, bad := range []string{"", "   ", "not base64 !!", base64.StdEncoding.EncodeToString(make([]byte, 16))} {
		if _, err := decodePin(bad); err == nil {
			t.Fatalf("decodePin accepted %q", bad)
		}
	}
}
