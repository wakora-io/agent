package defs

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"wakora.io/agent/internal/protocol"
)

const rdapBootstrapURL = "https://data.iana.org/rdap/dns.json"

var domainCache = struct {
	sync.Mutex
	expiry    map[string]time.Time
	fetchedAt map[string]time.Time
	bootstrap map[string]string
	bootAt    time.Time
}{expiry: map[string]time.Time{}, fetchedAt: map[string]time.Time{}}

func runDomain(o *Outcome, service string, p protocol.Probe, timeout time.Duration) {
	if len(p.Domains) == 0 {
		o.Check.Status = "fail"
		o.Check.Error = "no domains listed"
		return
	}
	o.Check.Target = strings.Join(p.Domains, ",")
	client := &http.Client{Timeout: timeout}

	var failures []string
	now := time.Now()
	for _, domain := range p.Domains {
		expiry, err := domainExpiry(client, domain, timeout)
		if err != nil {
			failures = append(failures, domain+": "+err.Error())
			continue
		}
		days := expiry.Sub(now).Hours() / 24
		tags := map[string]string{"domain": domain}
		o.Metrics = append(o.Metrics, protocol.MetricPoint{
			Name: "ext.domain.days_left", Value: float64(int(days*10)) / 10, Tags: tags,
		})
		payload, err := json.Marshal(map[string]string{"expiry": expiry.UTC().Format("2006-01-02")})
		if err == nil {
			o.InvFacts = append(o.InvFacts, protocol.Fact{Kind: "domain", Key: domain, Payload: string(payload)})
		}
	}
	if len(failures) == len(p.Domains) {
		o.Check.Status = "fail"
		o.Check.Error = strings.Join(failures, "; ")
		return
	}
	o.Check.Status = "ok"
	if len(failures) > 0 {
		o.Check.Error = strings.Join(failures, "; ")
	}
}

func domainExpiry(client *http.Client, domain string, timeout time.Duration) (time.Time, error) {
	domainCache.Lock()
	if exp, ok := domainCache.expiry[domain]; ok && time.Since(domainCache.fetchedAt[domain]) < 12*time.Hour {
		domainCache.Unlock()
		return exp, nil
	}
	domainCache.Unlock()

	exp, err := rdapExpiry(client, domain)
	if err != nil {
		exp, err = whoisExpiry(domain, timeout)
	}
	if err != nil {
		return time.Time{}, err
	}
	domainCache.Lock()
	domainCache.expiry[domain] = exp
	domainCache.fetchedAt[domain] = time.Now()
	domainCache.Unlock()
	return exp, nil
}

func rdapExpiry(client *http.Client, domain string) (time.Time, error) {
	base, err := rdapBase(client, tldOf(domain))
	if err != nil {
		return time.Time{}, err
	}
	resp, err := client.Get(base + "domain/" + domain)
	if err != nil {
		return time.Time{}, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, errRdap(resp.StatusCode)
	}
	var doc struct {
		Events []rdapEvent `json:"events"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return time.Time{}, err
	}
	return rdapExpirationEvent(doc.Events)
}

type rdapEvent struct {
	EventAction string `json:"eventAction"`
	EventDate   string `json:"eventDate"`
}

func rdapExpirationEvent(events []rdapEvent) (time.Time, error) {
	for _, e := range events {
		if e.EventAction != "expiration" {
			continue
		}
		if t, err := time.Parse(time.RFC3339, e.EventDate); err == nil {
			return t, nil
		}
	}
	return time.Time{}, errNoExpiry
}

func rdapBase(client *http.Client, tld string) (string, error) {
	domainCache.Lock()
	if domainCache.bootstrap != nil && time.Since(domainCache.bootAt) < 24*time.Hour {
		base, ok := domainCache.bootstrap[tld]
		domainCache.Unlock()
		if !ok {
			return "", errNoRdap
		}
		return base, nil
	}
	domainCache.Unlock()

	resp, err := client.Get(rdapBootstrapURL)
	if err != nil {
		return "", err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	resp.Body.Close()
	var boot struct {
		Services [][2][]string `json:"services"`
	}
	if err := json.Unmarshal(body, &boot); err != nil {
		return "", err
	}
	m := map[string]string{}
	for _, svc := range boot.Services {
		if len(svc[1]) == 0 {
			continue
		}
		url := svc[1][0]
		if !strings.HasSuffix(url, "/") {
			url += "/"
		}
		for _, t := range svc[0] {
			m[strings.ToLower(t)] = url
		}
	}
	domainCache.Lock()
	domainCache.bootstrap = m
	domainCache.bootAt = time.Now()
	base, ok := m[tld]
	domainCache.Unlock()
	if !ok {
		return "", errNoRdap
	}
	return base, nil
}

var whoisExpiryRe = regexp.MustCompile(`(?im)^\s*(?:registry expiry date|expiry date|expiration date|expiration time|paid-till|expires?(?: on)?)\s*[:.]?\s+(.+)$`)

var whoisLayouts = []string{
	time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02 15:04:05", "2006-01-02",
	"02.01.2006", "2006.01.02", "02-Jan-2006", "January 2, 2006",
}

func whoisExpiry(domain string, timeout time.Duration) (time.Time, error) {
	server, err := whoisQuery("whois.iana.org", tldOf(domain), timeout)
	if err != nil {
		return time.Time{}, err
	}
	ref := extractWhoisField(server, "whois")
	if ref == "" {
		return time.Time{}, errNoExpiry
	}
	raw, err := whoisQuery(ref, domain, timeout)
	if err != nil {
		return time.Time{}, err
	}
	return parseWhoisExpiry(raw)
}

func whoisQuery(server, query string, timeout time.Duration) (string, error) {
	conn, err := net.DialTimeout("tcp", server+":43", timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(query + "\r\n")); err != nil {
		return "", err
	}
	out, err := io.ReadAll(io.LimitReader(conn, 1<<20))
	if err != nil && len(out) == 0 {
		return "", err
	}
	return string(out), nil
}

func extractWhoisField(raw, field string) string {
	for _, line := range strings.Split(raw, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(k), field) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func parseWhoisExpiry(raw string) (time.Time, error) {
	m := whoisExpiryRe.FindStringSubmatch(raw)
	if len(m) < 2 {
		return time.Time{}, errNoExpiry
	}
	val := strings.TrimSpace(m[1])
	if i := strings.IndexByte(val, '('); i > 0 {
		val = strings.TrimSpace(val[:i])
	}
	for _, layout := range whoisLayouts {
		if t, err := time.Parse(layout, val); err == nil {
			return t, nil
		}
	}
	if fields := strings.Fields(val); len(fields) > 0 {
		for _, layout := range whoisLayouts {
			if t, err := time.Parse(layout, fields[0]); err == nil {
				return t, nil
			}
		}
	}
	return time.Time{}, errNoExpiry
}

func tldOf(domain string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSuffix(domain, ".")), ".")
	return parts[len(parts)-1]
}

type domainErr string

func (e domainErr) Error() string { return string(e) }

const (
	errNoExpiry domainErr = "expiry date not found"
	errNoRdap   domainErr = "tld has no rdap service"
)

func errRdap(code int) error {
	return domainErr("rdap status " + strconv.Itoa(code))
}
