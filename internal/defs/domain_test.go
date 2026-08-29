package defs

import (
	"testing"
	"time"
)

func TestRdapExpirationEvent(t *testing.T) {
	events := []rdapEvent{
		{EventAction: "registration", EventDate: "2020-01-01T00:00:00Z"},
		{EventAction: "expiration", EventDate: "2027-05-09T18:16:26Z"},
	}
	exp, err := rdapEventDate(events, "expiration")
	if err != nil {
		t.Fatal(err)
	}
	if exp.Year() != 2027 || exp.Month() != 5 {
		t.Fatalf("expiry parsed wrong: %v", exp)
	}
	reg, err := rdapEventDate(events, "registration")
	if err != nil {
		t.Fatal(err)
	}
	if reg.Year() != 2020 {
		t.Fatalf("registration parsed wrong: %v", reg)
	}
	if _, err := rdapEventDate([]rdapEvent{{EventAction: "registration", EventDate: "2020-01-01T00:00:00Z"}}, "expiration"); err == nil {
		t.Fatal("missing expiration event must error")
	}
}

func TestDNSConfirmedDead(t *testing.T) {
	dnsSuspect.Lock()
	dnsSuspect.m = map[string]int{}
	dnsSuspect.Unlock()

	if dnsConfirmedDead("flap.org", false) {
		t.Fatal("first NXDOMAIN must stay unconfirmed")
	}
	if dnsConfirmedDead("flap.org", true) {
		t.Fatal("alive resets and reports not dead")
	}
	if dnsConfirmedDead("flap.org", false) {
		t.Fatal("counter was reset by the live sweep - first NXDOMAIN again")
	}
	if !dnsConfirmedDead("flap.org", false) {
		t.Fatal("second consecutive NXDOMAIN must confirm")
	}
	if !dnsConfirmedDead("flap.org", false) {
		t.Fatal("stays confirmed while dead")
	}
}

func TestVhostRegistrable(t *testing.T) {
	cases := map[string]string{
		"www.example.com":     "example.com",
		"example.com":         "example.com",
		"a.b.shop.example.lv": "example.lv",
		"site.co.uk":          "site.co.uk",
		"www.site.co.uk":      "site.co.uk",
		"shop.site.com.au":    "site.com.au",
		"localhost":           "",
		"*.example.com":       "example.com",
		"192.0.2.10":          "",
	}
	for in, want := range cases {
		if got := vhostRegistrable(in); got != want {
			t.Fatalf("vhostRegistrable(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseWhoisExpiry(t *testing.T) {
	cases := map[string]time.Time{
		"Registry Expiry Date: 2027-05-09T18:16:26Z":       time.Date(2027, 5, 9, 18, 16, 26, 0, time.UTC),
		"Expiration Date: 2026-11-30":                      time.Date(2026, 11, 30, 0, 0, 0, 0, time.UTC),
		"paid-till: 2027.03.15":                            time.Date(2027, 3, 15, 0, 0, 0, 0, time.UTC),
		"   Expires: 02-Jan-2028":                          time.Date(2028, 1, 2, 0, 0, 0, 0, time.UTC),
		"expires on: 2026-12-01 14:30:00 (UTC+2)":          time.Date(2026, 12, 1, 14, 30, 0, 0, time.UTC),
		"Domain Name: x.lv\nExpiration Date: 2027-08-20\n": time.Date(2027, 8, 20, 0, 0, 0, 0, time.UTC),
	}
	for raw, want := range cases {
		got, err := parseWhoisExpiry(raw)
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		if !got.Equal(want) {
			t.Fatalf("parse %q = %v, want %v", raw, got, want)
		}
	}
	if _, err := parseWhoisExpiry("Domain Name: whatever\nStatus: ok\n"); err == nil {
		t.Fatal("no expiry line must error")
	}
}

func TestExtractWhoisFieldAndTld(t *testing.T) {
	raw := "domain: LV\norganisation: NIC\nwhois: whois.nic.lv\nstatus: ACTIVE\n"
	if got := extractWhoisField(raw, "whois"); got != "whois.nic.lv" {
		t.Fatalf("whois field = %q", got)
	}
	if tldOf("shop.example.co.uk") != "uk" || tldOf("wakora.io.") != "io" {
		t.Fatal("tld extraction wrong")
	}
}
