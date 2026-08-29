package agent

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wakora.io/agent/internal/config"
	"wakora.io/agent/internal/protocol"
)

func TestRumBeaconGate(t *testing.T) {
	a := &Agent{cfg: &config.Config{}, rum: make(chan []protocol.RumItem, 4)}
	a.rumAllowed.Store(map[string]bool{"shop.example.com": true})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/rum", strings.NewReader(`{"site":"WWW.Shop.example.com","path":"/checkout","ip":"203.0.113.9","trace":"0af7651916cd43dd8448eb211c80319c","vitals":{"lcp":1200}}`))
	a.handleRumBeacon(rec, req)
	if rec.Code != 204 {
		t.Fatalf("allowed beacon status = %d", rec.Code)
	}
	select {
	case items := <-a.rum:
		if len(items) != 1 || items[0].Site != "shop.example.com" {
			t.Fatalf("unexpected items %+v", items)
		}
		if items[0].IP != "203.0.113.9" {
			t.Fatalf("visitor ip not forwarded: %+v", items[0])
		}
		if items[0].Trace != "0af7651916cd43dd8448eb211c80319c" {
			t.Fatalf("trace not forwarded: %+v", items[0])
		}
	default:
		t.Fatal("beacon not forwarded")
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/v1/rum", strings.NewReader(`{"site":"shop.example.com","path":"/","ip":"not-an-ip","trace":"DROP TABLE"}`))
	a.handleRumBeacon(rec, req)
	if rec.Code != 204 {
		t.Fatalf("bad-ip beacon status = %d", rec.Code)
	}
	select {
	case items := <-a.rum:
		if items[0].IP != "" {
			t.Fatalf("garbage ip must be dropped: %+v", items[0])
		}
		if items[0].Trace != "" {
			t.Fatalf("garbage trace must be dropped: %+v", items[0])
		}
	default:
		t.Fatal("bad-ip beacon not forwarded")
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest("POST", "/v1/rum", strings.NewReader(`{"site":"other.example.com","path":"/"}`))
	a.handleRumBeacon(rec, req)
	if rec.Code != 204 {
		t.Fatalf("denied beacon status = %d", rec.Code)
	}
	select {
	case <-a.rum:
		t.Fatal("denied site forwarded")
	default:
	}
}

func TestRumSitesFile(t *testing.T) {
	dir := t.TempDir()

	writeRumSites(dir, []string{"a.com", "b.com"})
	data, err := os.ReadFile(filepath.Join(dir, "rum-sites.php"))
	if err != nil {
		t.Fatalf("rum-sites.php not written: %v", err)
	}
	got := string(data)
	if !strings.Contains(got, "'a.com'=>1") || !strings.Contains(got, "'b.com'=>1") {
		t.Fatalf("unexpected content: %s", got)
	}

	writeRumSites(dir, nil)
	data, err = os.ReadFile(filepath.Join(dir, "rum-sites.php"))
	if err != nil {
		t.Fatalf("empty list must rewrite, not remove: %v", err)
	}
	if !strings.Contains(string(data), "return [];") {
		t.Fatalf("empty list content: %s", string(data))
	}
}

func TestRumSitesFileRejectsHostileNames(t *testing.T) {
	dir := t.TempDir()

	writeRumSites(dir, []string{`evil.com\`, "x'y.com", "a b.com", "inj.com'=>1];phpinfo();//", "good.example.com"})
	data, err := os.ReadFile(filepath.Join(dir, "rum-sites.php"))
	if err != nil {
		t.Fatalf("rum-sites.php not written: %v", err)
	}
	got := string(data)
	if got != "<?php return ['good.example.com'=>1];\n" {
		t.Fatalf("hostile names leaked into the file: %s", got)
	}
	if strings.ContainsAny(got, `\"`) || strings.Contains(got, "phpinfo") {
		t.Fatalf("dangerous bytes in file: %s", got)
	}
}
