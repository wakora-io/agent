package defs

import (
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"wakora.io/agent/internal/protocol"
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
		"www.example.com":            "example.com",
		"example.com":                "example.com",
		"a.b.shop.example.lv":        "example.lv",
		"site.co.uk":                 "site.co.uk",
		"www.site.co.uk":             "site.co.uk",
		"shop.site.com.au":           "site.com.au",
		"portal.id.lv":               "portal.id.lv",
		"files.parents.portal.id.lv": "portal.id.lv",
		"app.198-51-100-7.nip.io":    "",
		"demo.example.github.io":     "",
		"burn.example.test":          "",
		"node.example.lab":           "",
		"localhost":                  "",
		"*.example.com":              "example.com",
		"192.0.2.10":                 "",
		"com":                        "",
		"www.xn--e1afmkfd.org":       "xn--e1afmkfd.org",
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

func TestParseWhoisDateFormats(t *testing.T) {
	cases := map[string]time.Time{
		"4.7.2027 10:15:55":           time.Date(2027, 7, 4, 10, 15, 55, 0, time.UTC),
		"2027-Aug-25.":                time.Date(2027, 8, 25, 0, 0, 0, 0, time.UTC),
		"2027/05/31":                  time.Date(2027, 5, 31, 0, 0, 0, 0, time.UTC),
		"September  5 2027":           time.Date(2027, 9, 5, 0, 0, 0, 0, time.UTC),
		"Mon Mar 22 23:59:00 2027":    time.Date(2027, 3, 22, 23, 59, 0, 0, time.UTC),
		"05-06-2027":                  time.Date(2027, 6, 5, 0, 0, 0, 0, time.UTC),
		"16/08/2027 23:59:39":         time.Date(2027, 8, 16, 23, 59, 39, 0, time.UTC),
		"20270606":                    time.Date(2027, 6, 6, 0, 0, 0, 0, time.UTC),
		"2027. 03. 02.":               time.Date(2027, 3, 2, 0, 0, 0, 0, time.UTC),
		"20-Mar-2027 13:16:16":        time.Date(2027, 3, 20, 13, 16, 16, 0, time.UTC),
		"2030-02-08 21:00:00 CLST":    time.Date(2030, 2, 8, 0, 0, 0, 0, time.UTC),
		"2027-03-15T21:00:00Z":        time.Date(2027, 3, 15, 21, 0, 0, 0, time.UTC),
		"22-mar-2027":                 time.Date(2027, 3, 22, 0, 0, 0, 0, time.UTC),
		".........2030-06-26":         time.Date(2030, 6, 26, 0, 0, 0, 0, time.UTC),
		"2027-06-20 00:00:00 (UTC+3)": time.Date(2027, 6, 20, 0, 0, 0, 0, time.UTC),
	}
	for raw, want := range cases {
		got, sentinel, err := parseWhoisDate(strings.TrimLeft(raw, "."))
		if err != nil || sentinel {
			t.Fatalf("parse %q: err=%v sentinel=%v", raw, err, sentinel)
		}
		if !got.Equal(want) {
			t.Fatalf("parse %q = %v, want %v", raw, got, want)
		}
	}
	for _, raw := range []string{"Never", "N/A", "9999. 12. 31.", "none", "-"} {
		if _, sentinel, err := parseWhoisDate(raw); err != nil || !sentinel {
			t.Fatalf("%q must read as a no-expiry sentinel (err=%v sentinel=%v)", raw, err, sentinel)
		}
	}
	if _, _, err := parseWhoisDate("30th April 2003"); err == nil {
		t.Fatal("an unknown date shape must error, not guess")
	}
}

func TestWhoisFieldsAcrossRegistries(t *testing.T) {
	cases := []struct {
		raw  string
		want time.Time
	}{
		{"domain.............: example.fi\nexpires............: 4.7.2027 10:15:55\n", time.Date(2027, 7, 4, 10, 15, 55, 0, time.UTC)},
		{"** Domain Name: example.com.tr\nExpires on..............: 2027-Aug-25.\n", time.Date(2027, 8, 25, 0, 0, 0, 0, time.UTC)},
		{"[Domain Name]                   EXAMPLE.JP\n[Created on]                    2015/03/01\n[Expires on]                    2027/05/31\n", time.Date(2027, 5, 31, 0, 0, 0, 0, time.UTC)},
		{"domain:       example.is\nexpires:      September  5 2027\n", time.Date(2027, 9, 5, 0, 0, 0, 0, time.UTC)},
		{"Domain example.kg\nRecord created: Wed Mar 22 10:00:00 2017\nRecord expires on: Mon Mar 22 23:59:00 2027\n", time.Date(2027, 3, 22, 23, 59, 0, 0, time.UTC)},
		{"domain:        example.co.il\nvalidity:     05-06-2027\n", time.Date(2027, 6, 5, 0, 0, 0, 0, time.UTC)},
		{"Domain Name: example.hk\nExpiry Date: 16-11-2035\n", time.Date(2035, 11, 16, 0, 0, 0, 0, time.UTC)},
		{"domain:      example.com.br\nexpires:     20270606\n", time.Date(2027, 6, 6, 0, 0, 0, 0, time.UTC)},
		{"Domain Name: example.it\nExpire Date: 2027-04-02\n", time.Date(2027, 4, 2, 0, 0, 0, 0, time.UTC)},
		{"Domain: example.sk\nValid Until: 2027-06-10\n", time.Date(2027, 6, 10, 0, 0, 0, 0, time.UTC)},
		{"Domain Name: example.hr\nRegistrar Registration Expiration Date: 2026-11-29T00:00:00Z\n", time.Date(2026, 11, 29, 0, 0, 0, 0, time.UTC)},
		{"Domain Name: example.us\nRegistry Expiry Date: 2026-09-11T23:59:59Z\nRegistrar Registration Expiration Date: 2030-01-01T00:00:00Z\n", time.Date(2026, 9, 11, 23, 59, 59, 0, time.UTC)},
		{"Domaine: example.sn\nDate d'expiration: 2027-03-06T00:00:00Z\n", time.Date(2027, 3, 6, 0, 0, 0, 0, time.UTC)},
		{"Domain: example.tg\nExpiration:.........2030-06-26\n", time.Date(2030, 6, 26, 0, 0, 0, 0, time.UTC)},
	}
	for _, c := range cases {
		var info domainInfo
		applyWhois(&info, c.raw)
		if !info.hasExpiry || !info.expiry.Equal(c.want) {
			t.Fatalf("whois %q: hasExpiry=%v expiry=%v err=%q, want %v", c.raw, info.hasExpiry, info.expiry, info.err, c.want)
		}
		if info.unparsed || info.transient {
			t.Fatalf("whois %q flagged unparsed=%v transient=%v", c.raw, info.unparsed, info.transient)
		}
	}
}

func TestApplyWhoisClassifiesAnswers(t *testing.T) {
	var info domainInfo
	applyWhois(&info, "Number of allowed queries exceeded.\n")
	if !info.transient || info.hasExpiry {
		t.Fatalf("a registry rate limit is transient, got %+v", info)
	}
	info = domainInfo{}
	applyWhois(&info, "No Data Found\n>>> Last update of WHOIS database: 2026-09-10T20:40:41Z <<<\n")
	if info.transient || info.unparsed || info.hasExpiry || info.err == "" {
		t.Fatalf("not-found is a settled negative, got %+v", info)
	}
	info = domainInfo{}
	applyWhois(&info, "Domain Name: example.gg\nRegistered on 30th April 2003 at 00:00:00.000\nRegistrar:\n   Example Ltd\n")
	if !info.unparsed || info.hasExpiry {
		t.Fatalf("a record without an expiry field is unparsed, got %+v", info)
	}
	info = domainInfo{}
	applyWhois(&info, "Domain Name: example.kr\nRegistered Date         : 2015. 03. 02.\nExpiration Date         : 9999. 12. 31.\n")
	if info.hasExpiry || info.unparsed || !info.hasReg {
		t.Fatalf("a sentinel expiry is no-expiry with the registration kept, got %+v", info)
	}
	info = domainInfo{}
	applyWhois(&info, "Domain Name: example.io\nCreation Date: 2016-01-02T03:04:05Z\nRegistry Expiry Date: 2027-01-02T03:04:05Z\nNOTICE: The expiration date displayed in this record is the date the registrar's sponsorship of the domain name registration in the registry is currently set to expire. This date does not necessarily reflect the expiration date of the domain name registrant's agreement with the sponsoring registrar. Users may consult the sponsoring registrar's Whois database to view the registrar's reported date of expiration for this registration. Query rate exceeded? no.\n")
	if !info.hasExpiry || !info.hasReg || info.source != "whois" {
		t.Fatalf("a full record with a chatty disclaimer must still parse, got %+v", info)
	}
}

func TestDomainTTLTiers(t *testing.T) {
	far := domainInfo{hasExpiry: true, expiry: time.Now().Add(120 * 24 * time.Hour)}
	near := domainInfo{hasExpiry: true, expiry: time.Now().Add(30 * 24 * time.Hour)}
	close := domainInfo{hasExpiry: true, expiry: time.Now().Add(5 * 24 * time.Hour)}
	if domainTTL(far) != domainTTLFar || domainTTL(near) != domainTTLNear || domainTTL(close) != domainTTLClose {
		t.Fatal("expiry distance must pick the week/day/6h tier")
	}
	if domainTTL(domainInfo{transient: true}) != domainTTLTransient {
		t.Fatal("a transient failure retries within the hour")
	}
	if domainTTL(domainInfo{unparsed: true}) != domainTTLUnparsed {
		t.Fatal("an unparsed answer waits a day")
	}
	if domainTTL(domainInfo{err: "not found"}) != domainTTLFar {
		t.Fatal("a settled no-expiry answer waits a week")
	}
}

func TestDomainStoreKeepsDatesThroughTransientFailures(t *testing.T) {
	domainStore.Lock()
	domainStore.recs = map[string]domainRecord{}
	domainStore.path = ""
	domainStore.loaded = true
	domainStore.Unlock()

	exp := time.Date(2027, 5, 9, 18, 16, 26, 0, time.UTC)
	domainRemember("example.com", domainInfo{hasExpiry: true, expiry: exp, source: "rdap"})
	info, fresh, known := domainKnown("example.com")
	if !known || !fresh || !info.hasExpiry || !info.expiry.Equal(exp) {
		t.Fatalf("stored record lost: %+v fresh=%v known=%v", info, fresh, known)
	}
	got := domainRemember("example.com", domainInfo{transient: true, err: "rdap answered 429"})
	if !got.hasExpiry || !got.expiry.Equal(exp) || got.source != "rdap" {
		t.Fatalf("a transient failure must keep the last known dates, got %+v", got)
	}
	info, _, _ = domainKnown("example.com")
	if info.err != "rdap answered 429" || !info.hasExpiry {
		t.Fatalf("record after transient: %+v", info)
	}
	if !domainInsightDue("example.com", "2026-09-10") || domainInsightDue("example.com", "2026-09-10") {
		t.Fatal("the 30-day insight fires once per day per domain")
	}
	if !domainInsightDue("example.com", "2026-09-11") {
		t.Fatal("a new day re-arms the insight")
	}
	if _, _, known := domainKnown("nothing.example"); known {
		t.Fatal("unknown domain must not be known")
	}
}

func TestLookupRelayFallsBackWhenEgressIsBlocked(t *testing.T) {
	domainStore.Lock()
	domainStore.blocked = map[string]time.Time{"rdap": time.Now().Add(time.Hour), "whois": time.Now().Add(time.Hour)}
	domainStore.Unlock()
	defer func() {
		domainStore.Lock()
		domainStore.blocked = map[string]time.Time{}
		domainStore.Unlock()
		SetLookupRelay(nil)
	}()
	var seen []protocol.Lookup
	SetLookupRelay(func(req protocol.Lookup) (protocol.LookupResult, error) {
		seen = append(seen, req)
		if req.Kind == "rdap" {
			return protocol.LookupResult{Nonce: req.Nonce, Error: "no rdap service for this tld"}, nil
		}
		return protocol.LookupResult{Nonce: req.Nonce, Body: "Domain Name: example.us\nRegistry Expiry Date: 2026-09-11T23:59:59Z\n"}, nil
	})
	info := lookupDomain(&http.Client{Timeout: time.Second}, "example.us", time.Second)
	if !info.hasExpiry || !info.relayed || info.source != "whois" {
		t.Fatalf("relayed lookup: %+v", info)
	}
	if len(seen) != 2 || seen[0].Kind != "rdap" || seen[1].Kind != "whois" || seen[1].Query != "example.us" || seen[1].Domain != "example.us" {
		t.Fatalf("relay requests: %+v", seen)
	}
	SetLookupRelay(nil)
	info = lookupDomain(&http.Client{Timeout: time.Second}, "example.us", time.Second)
	if !info.transient || info.hasExpiry {
		t.Fatalf("blocked egress without a relay is a transient failure, got %+v", info)
	}
}

func TestNetBlockedClassifiesDialFailures(t *testing.T) {
	if !netBlocked(&net.OpError{Op: "dial", Err: errors.New("connection refused")}) {
		t.Fatal("a refused dial means the egress is closed")
	}
	if !netBlocked(&net.DNSError{Err: "no such host", Name: "rdap.example"}) {
		t.Fatal("a failing resolver is a blocked path too")
	}
	if netBlocked(&net.OpError{Op: "read", Err: errors.New("i/o timeout")}) {
		t.Fatal("a slow registry is not a blocked egress")
	}
	if !netBlocked(errors.New("Get \"https://x\": tls: failed to verify certificate: x509: certificate signed by unknown authority")) {
		t.Fatal("tls interception counts as blocked")
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
