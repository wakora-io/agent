package defs

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"wakora.io/agent/internal/protocol"
	"wakora.io/agent/internal/secret"
)

func authServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "monitor" || p != "pw" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("linstor_resource_definition_count 7\n"))
	}))
}

func TestHTTPSecretOptionalUnsetHints(t *testing.T) {
	srv := authServer(t)
	defer srv.Close()
	var o Outcome
	p := protocol.Probe{Name: "metrics", Type: "http", URL: srv.URL, SecretOpt: "linstor-api"}
	runHTTP(&o, p, 5*time.Second, func(string) (secret.Cred, bool) { return secret.Cred{}, false })
	if o.Check.Status != "fail" {
		t.Fatalf("want fail, got %s", o.Check.Status)
	}
	if !strings.Contains(o.Check.Error, "wakora secret set linstor-api") {
		t.Fatalf("hint missing: %s", o.Check.Error)
	}
}

func TestHTTPSecretOptionalResolvedAuthenticates(t *testing.T) {
	srv := authServer(t)
	defer srv.Close()
	var o Outcome
	p := protocol.Probe{Name: "metrics", Type: "http", URL: srv.URL, SecretOpt: "linstor-api",
		Prom: []protocol.PromRule{{Name: "svc.linstor-controller.resource_definitions", Metric: "linstor_resource_definition_count"}}}
	runHTTP(&o, p, 5*time.Second, func(name string) (secret.Cred, bool) {
		if name != "linstor-api" {
			t.Fatalf("wrong secret name %s", name)
		}
		return secret.Cred{User: "monitor", Pass: "pw"}, true
	})
	if o.Check.Status != "ok" {
		t.Fatalf("want ok, got %s (%s)", o.Check.Status, o.Check.Error)
	}
	if len(o.Metrics) != 1 || o.Metrics[0].Value != 7 {
		t.Fatalf("prom parse: %+v", o.Metrics)
	}
}

func TestHTTPSecretOptionalOpenEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	var o Outcome
	p := protocol.Probe{Name: "metrics", Type: "http", URL: srv.URL, SecretOpt: "linstor-api"}
	runHTTP(&o, p, 5*time.Second, func(string) (secret.Cred, bool) { return secret.Cred{}, false })
	if o.Check.Status != "ok" {
		t.Fatalf("open endpoint must pass without a secret: %s", o.Check.Error)
	}
}

func TestHTTPBearerHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok123" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	var o Outcome
	p := protocol.Probe{Name: "metrics", Type: "http", URL: srv.URL, SecretOpt: "linstor-controller", Bearer: true}
	runHTTP(&o, p, 5*time.Second, func(string) (secret.Cred, bool) {
		return secret.Cred{User: "token", Pass: "tok123"}, true
	})
	if o.Check.Status != "ok" {
		t.Fatalf("bearer auth failed: %s", o.Check.Error)
	}
}

func TestHTTPURLsWalkToAnsweringEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := dead.URL
	dead.Close()
	var o Outcome
	p := protocol.Probe{Name: "metrics", Type: "http", URLs: []string{deadURL, srv.URL}}
	runHTTP(&o, p, 5*time.Second, func(string) (secret.Cred, bool) { return secret.Cred{}, false })
	if o.Check.Status != "ok" {
		t.Fatalf("urls walk did not reach the live endpoint: %s", o.Check.Error)
	}
	if o.Check.Target != srv.URL {
		t.Fatalf("target %s, want %s", o.Check.Target, srv.URL)
	}
}

func TestHTTPURLsAllDeadReportsError(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := dead.URL
	dead.Close()
	var o Outcome
	p := protocol.Probe{Name: "metrics", Type: "http", URLs: []string{deadURL}}
	runHTTP(&o, p, 5*time.Second, func(string) (secret.Cred, bool) { return secret.Cred{}, false })
	if o.Check.Status != "fail" || o.Check.Error == "" {
		t.Fatalf("dead endpoints must fail with the last error: %+v", o.Check)
	}
}

func TestHTTPInsecureAcceptsSelfSigned(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	var o Outcome
	p := protocol.Probe{Name: "metrics", Type: "http", URL: srv.URL}
	runHTTP(&o, p, 5*time.Second, func(string) (secret.Cred, bool) { return secret.Cred{}, false })
	if o.Check.Status != "fail" {
		t.Fatal("self-signed without insecure must fail verification")
	}
	var o2 Outcome
	p.Insecure = true
	runHTTP(&o2, p, 5*time.Second, func(string) (secret.Cred, bool) { return secret.Cred{}, false })
	if o2.Check.Status != "ok" {
		t.Fatalf("insecure did not accept self-signed: %s", o2.Check.Error)
	}
}
