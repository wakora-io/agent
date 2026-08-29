package defs

import "testing"

const appcmdSites = `SITE "Default Web Site" (id:1,bindings:http/*:80:,state:Started)
SITE "Shop" (id:2,bindings:http/*:8081:,https/*:8443:,state:Stopped)
`

const appcmdPools = `APPPOOL "DefaultAppPool" (MgdVersion:v4.0,MgdMode:Integrated,state:Started)
APPPOOL ".NET v4.5" (MgdVersion:v4.0,MgdMode:Integrated,state:Stopped)
`

func TestParseAppcmdSites(t *testing.T) {
	got := parseAppcmd(appcmdSites, "SITE")
	if len(got) != 2 {
		t.Fatalf("want 2 sites, got %d: %v", len(got), got)
	}
	if got["Default Web Site"] != "Started" {
		t.Fatalf("default site state: %q", got["Default Web Site"])
	}
	if got["Shop"] != "Stopped" {
		t.Fatalf("shop state: %q", got["Shop"])
	}
}

func TestParseAppcmdPools(t *testing.T) {
	got := parseAppcmd(appcmdPools, "APPPOOL")
	if got["DefaultAppPool"] != "Started" {
		t.Fatalf("pool state: %q", got["DefaultAppPool"])
	}
	if got[".NET v4.5"] != "Stopped" {
		t.Fatalf("pool state: %q", got[".NET v4.5"])
	}
}

func TestParseAppcmdIgnoresOther(t *testing.T) {
	if got := parseAppcmd(appcmdSites, "APPPOOL"); len(got) != 0 {
		t.Fatalf("expected empty, got %v", got)
	}
}

func TestParseIISSitesBindings(t *testing.T) {
	out := `SITE "Default Web Site" (id:1,bindings:http/*:8080:site.example.com,http/*:80:,state:Started)
SITE "Shop" (id:2,bindings:https/*:8443:shop.example.com,http/*:8081:shop.example.com,state:Stopped)
SITE "Bare" (id:3,bindings:http/*:9090:,state:Started)
`
	sites := parseIISSites(out)
	if len(sites) != 3 {
		t.Fatalf("want 3 sites, got %d", len(sites))
	}
	if sites[0].name != "Default Web Site" || sites[0].state != "Started" {
		t.Fatalf("site0: %+v", sites[0])
	}
	if len(sites[0].hosts) != 1 || sites[0].hosts[0] != "site.example.com" {
		t.Fatalf("site0 hosts: %v", sites[0].hosts)
	}
	if len(sites[1].hosts) != 1 || sites[1].hosts[0] != "shop.example.com" {
		t.Fatalf("site1 hosts must dedupe: %v", sites[1].hosts)
	}
	if len(sites[2].hosts) != 0 {
		t.Fatalf("bare binding must carry no hosts: %v", sites[2].hosts)
	}
}
