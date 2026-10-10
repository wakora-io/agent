package defs

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func TestVhostAliasesAreTheNonPrimaryNames(t *testing.T) {
	hosts := []vhost{
		{Name: "a.example.com", Port: 443, Primary: true},
		{Name: "www.a.example.com", Port: 443},
		{Name: "_", Port: 80},
		{Name: "localhost", Port: 80},
		{Name: "*.a.example.com", Port: 443},
		{Name: "~^(?<sub>.+)\\.example\\.com$", Port: 443},
		{Name: "alias.example.net", Port: 80, Redirect: "a.example.com"},
	}
	got := map[string]bool{}
	for _, i := range vhostAliases(hosts) {
		got[fmt.Sprintf("%s:%d", hosts[i].Name, hosts[i].Port)] = true
	}
	want := map[string]bool{"www.a.example.com:443": true, "alias.example.net:80": true}
	if len(got) != len(want) {
		t.Fatalf("aliases %v, want %v", got, want)
	}
	for k := range want {
		if !got[k] {
			t.Fatalf("aliases %v miss %s", got, k)
		}
	}
}

func TestVhostAliasesFromNginxBlocks(t *testing.T) {
	hosts := parseNginxVhosts([]byte(nginxPanelDump))
	got := map[string]bool{}
	for _, i := range vhostAliases(hosts) {
		got[fmt.Sprintf("%s:%d", hosts[i].Name, hosts[i].Port)] = true
	}
	for _, k := range []string{"www.a.example.lv:80", "www.c.example.lv:8080"} {
		if !got[k] {
			t.Errorf("alias %s not selected (got %v)", k, got)
		}
	}
	for _, k := range []string{"a.example.lv:80", "b.example.lv:443", "c.example.lv:8080"} {
		if got[k] {
			t.Errorf("primary %s selected as alias", k)
		}
	}
}

func TestProbeVhostCertReadsTheAliasCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("certificate probe sent an HTTP request: %s %s", r.Method, r.URL)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	r := probeVhostCert(vhost{Name: "www.example.com", Port: port}, 2*time.Second)
	if !r.hasSSL {
		t.Fatal("no certificate read")
	}
	if r.sslDays <= 0 {
		t.Fatalf("days left %.1f", r.sslDays)
	}
	if r.trusted {
		t.Fatal("a self-signed test certificate read as trusted")
	}
	if !r.nameOK {
		t.Fatal("a certificate for *.example.com read as not covering www.example.com")
	}
	if other := probeVhostCert(vhost{Name: "shop.example.net", Port: port}, 2*time.Second); !other.hasSSL || other.nameOK {
		t.Fatalf("a certificate for example.com read for shop.example.net: ssl=%v nameOK=%v", other.hasSSL, other.nameOK)
	}
}

func TestProbeVhostCertPlainPortHasNoCertificate(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			c.Close()
		}
	}()
	r := probeVhostCert(vhost{Name: "www.example.com", Port: ln.Addr().(*net.TCPAddr).Port}, time.Second)
	if r.hasSSL {
		t.Fatal("plain port read as TLS")
	}
}
