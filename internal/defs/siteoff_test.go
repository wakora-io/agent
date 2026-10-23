package defs

import "testing"

func TestSitesBeyondThePlanLeaveTheProbeLists(t *testing.T) {
	defer SetSitesOff(nil)
	hosts := []vhost{
		{Name: "off.example.com", Port: 443, Primary: true},
		{Name: "www.off.example.com", Port: 443, Block: "off.example.com"},
		{Name: "on.example.com", Port: 443, Primary: true},
		{Name: "www.on.example.com", Port: 443, Block: "on.example.com"},
	}
	SetSitesOff([]string{"OFF.example.com"})
	if !siteOff("www.off.example.com") || !siteOff("off.example.com") || siteOff("on.example.com") {
		t.Fatal("the site key does not fold case and www")
	}
	aliases := vhostAliases(hosts)
	if len(aliases) != 1 || hosts[aliases[0]].Name != "www.on.example.com" {
		t.Fatalf("aliases = %v", aliases)
	}
	SetSitesOff(nil)
	if siteOff("off.example.com") || len(vhostAliases(hosts)) != 2 {
		t.Fatal("an empty list must probe every site again")
	}
}
