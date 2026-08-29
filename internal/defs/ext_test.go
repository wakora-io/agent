package defs

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"
)

func TestProbeExternalHealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("welcome to the site"))
	}))
	defer srv.Close()

	r := probeExternal(srv.URL, 0, nil, 5*time.Second)
	if !r.up {
		t.Fatalf("healthy site not up: %+v", r)
	}
	if r.status != 200 {
		t.Fatalf("status %d", r.status)
	}
	if r.hasSSL {
		t.Fatal("plain http reported ssl")
	}
}

func TestProbeExternalTLSUntrusted(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	r := probeExternal(srv.URL, 0, nil, 5*time.Second)
	if !r.hasSSL {
		t.Fatal("tls server not detected")
	}
	if r.trusted {
		t.Fatal("httptest self-signed cert must be untrusted")
	}
	if r.sslDays <= 0 {
		t.Fatalf("ssl days should be positive for a fresh cert: %v", r.sslDays)
	}
	if !r.up {
		t.Fatal("untrusted cert must not mark the site down (200 responds)")
	}
}

func TestProbeExternalDownOn5xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	}))
	defer srv.Close()

	r := probeExternal(srv.URL, 0, nil, 5*time.Second)
	if r.up {
		t.Fatal("503 must be down")
	}
	if r.status != 503 {
		t.Fatalf("status %d", r.status)
	}
}

func TestProbeExternalBodyAssertion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<title>Login</title>"))
	}))
	defer srv.Close()

	re := regexp.MustCompile("Login")
	if r := probeExternal(srv.URL, 0, re, 5*time.Second); !r.up || !r.bodyMatch {
		t.Fatalf("body assertion should pass: %+v", r)
	}
	reMiss := regexp.MustCompile("Dashboard")
	if r := probeExternal(srv.URL, 0, reMiss, 5*time.Second); r.up || r.bodyMatch {
		t.Fatalf("body assertion should fail and mark down: %+v", r)
	}
}

func TestProbeExternalConnRefused(t *testing.T) {
	r := probeExternal("http://127.0.0.1:1", 0, nil, 2*time.Second)
	if r.up {
		t.Fatal("connection refused must be down")
	}
	if r.note == "" {
		t.Fatal("down result must carry a note")
	}
}
