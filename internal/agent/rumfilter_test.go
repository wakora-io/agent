package agent

import (
	"testing"

	"wakora.io/agent/internal/discovery"
)

func TestFilterSitesKeepsOnlyWhatThisHostServes(t *testing.T) {
	got := filterSitesByVhosts(
		[]string{"shop.example.com", "blog.example.net", "other.example.org"},
		[]string{"shop.example.com:443", "www.blog.example.net:80"},
	)
	if len(got) != 2 || got[0] != "shop.example.com" || got[1] != "blog.example.net" {
		t.Fatalf("got %v", got)
	}
}

func TestFilterSitesLeavesEverythingWhenNoVhostsAreKnown(t *testing.T) {
	sites := []string{"shop.example.com"}
	if got := filterSitesByVhosts(sites, nil); len(got) != 1 {
		t.Fatalf("a host whose config scan failed must keep serving RUM: %v", got)
	}
}

func TestFilterSitesDropsForeignSitesEntirely(t *testing.T) {
	got := filterSitesByVhosts(
		[]string{"shop.example.com", "blog.example.net"},
		[]string{"internal.example.org:80"},
	)
	if len(got) != 0 {
		t.Fatalf("sites hosted elsewhere must not reach this box: %v", got)
	}
}

func TestFilterSitesMatchesAWildcardVhost(t *testing.T) {
	got := filterSitesByVhosts([]string{"a.example.com", "b.example.org"}, []string{"*.example.com:443"})
	if len(got) != 1 || got[0] != "a.example.com" {
		t.Fatalf("got %v", got)
	}
}

func TestVhostKeysReadsTheInventory(t *testing.T) {
	a := &Agent{facts: []discovery.Fact{
		{Kind: "vhost", Key: "shop.example.com:443"},
		{Kind: "port", Key: "443/tcp"},
		{Kind: "vhost", Key: "blog.example.net:80"},
	}}
	got := a.vhostKeys()
	if len(got) != 2 {
		t.Fatalf("got %v", got)
	}
}

func TestVhostSiteNameStripsPortAndWww(t *testing.T) {
	cases := map[string]string{
		"www.example.com:443": "example.com",
		"example.com":         "example.com",
		"example.com:8080":    "example.com",
		"host:notaport":       "host:notaport",
	}
	for in, want := range cases {
		if got := vhostSiteName(in); got != want {
			t.Errorf("vhostSiteName(%q) = %q, want %q", in, got, want)
		}
	}
}
