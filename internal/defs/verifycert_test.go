package defs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func testChain(t *testing.T, names ...string) []*x509.Certificate {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "wakora test ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(ca)
	prev := certRoots
	certRoots = pool
	t.Cleanup(func() { certRoots = prev })
	return []*x509.Certificate{leaf, ca}
}

func TestVerifyCertAcceptsTheRequestedHost(t *testing.T) {
	chain := testChain(t, "shop.example.com", "www.shop.example.com")
	if note := verifyCert(chain, "shop.example.com"); note != "" {
		t.Fatalf("a matching certificate was reported as %q", note)
	}
	if note := verifyCert(chain, "www.shop.example.com"); note != "" {
		t.Fatalf("a SAN entry was reported as %q", note)
	}
}

func TestVerifyCertRejectsAValidCertificateForAnotherHost(t *testing.T) {
	chain := testChain(t, "other.example.com")
	if note := verifyCert(chain, "shop.example.com"); note != "certificate is for another host" {
		t.Fatalf("a trusted certificate issued to another name was reported as %q", note)
	}
}

func TestVerifyCertWithoutAHostStillChecksTheChain(t *testing.T) {
	chain := testChain(t, "other.example.com")
	if note := verifyCert(chain, ""); note != "" {
		t.Fatalf("chain verdict changed when no host was given: %q", note)
	}
	certRoots = x509.NewCertPool()
	if note := verifyCert(chain, "other.example.com"); note != "untrusted certificate" {
		t.Fatalf("an unrooted chain was reported as %q", note)
	}
}
