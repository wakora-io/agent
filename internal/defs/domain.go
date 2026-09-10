package defs

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"wakora.io/agent/internal/atomicfile"
	"wakora.io/agent/internal/protocol"
)

const rdapBootstrapURL = "https://data.iana.org/rdap/dns.json"

const (
	domainRelayWait    = 15 * time.Second
	domainBlockedFor   = time.Hour
	domainTTLFar       = 7 * 24 * time.Hour
	domainTTLNear      = 24 * time.Hour
	domainTTLClose     = 6 * time.Hour
	domainTTLTransient = time.Hour
	domainTTLUnparsed  = 24 * time.Hour
	domainInsightDays  = 30
	whoisServerTTL     = 24 * time.Hour
	whoisReadMax       = 64 << 10
	rdapReadMax        = 256 << 10
)

var noExpiryTLD = map[string]bool{
	"lv": true, "eu": true, "de": true, "nl": true, "no": true, "at": true, "be": true, "ch": true, "li": true,
	"hu": true, "lu": true, "es": true, "pt": true, "gr": true, "bg": true, "ae": true, "sa": true, "qa": true,
	"om": true, "pe": true, "nz": true, "gg": true, "je": true, "aw": true, "kz": true, "sm": true, "ir": true,
	"mq": true, "gf": true, "gp": true, "cf": true, "tk": true, "gq": true, "sx": true, "hm": true, "iq": true,
	"jo": true, "sb": true,
}

var whoisQuerySuffix = map[string]string{"jp": "/e"}

var whoisExpiryKeys = []string{
	"registryexpirydate", "expirydate", "expirationdate", "expirationtime", "domainexpirationdate",
	"expireson", "expires", "expiresat", "expire", "expiredate", "expiration", "paidtill", "validuntil",
	"validity", "renewaldate", "recordexpireson", "datedexpiration", "fechadevencimiento",
	"registrarregistrationexpirationdate",
}

var whoisCreatedKeys = []string{
	"creationdate", "registrationdate", "registrationtime", "domainregistrationdate", "createdon", "created",
	"createddate", "registered", "registeredon", "registereddate", "recordcreatedon", "recordcreated",
	"assigneddate", "datedecreation", "fechaderegistro", "activated",
}

var whoisRecordKeys = []string{"domainname", "domain", "nameserver", "nserver", "registrar", "registrant", "created", "creationdate", "registered"}

var whoisLayouts = []string{
	time.RFC3339, time.RFC3339Nano, "2006-01-02T15:04:05Z", "2006-01-02T15:04:05.000Z", "2006-01-02 15:04:05",
	"2006-01-02", "20060102", "02.01.2006 15:04:05", "02.01.2006", "2.1.2006 15:04:05", "2.1.2006",
	"2006.01.02 15:04:05", "2006.01.02", "02-Jan-2006 15:04:05", "02-Jan-2006", "2-Jan-2006", "2006-Jan-02",
	"January 2, 2006", "January 2 2006", "2 January 2006", "02 Jan 2006", "02-01-2006", "02/01/2006 15:04:05",
	"02/01/2006", "2006/01/02", "2006. 01. 02", "Mon Jan 2 15:04:05 2006",
}

var whoisRateLimitRe = regexp.MustCompile(`(?i)(rate limit|ratelimit|too many|quota|exceeded|not permitted|try again later|access denied|blocked)`)

var whoisNotFoundRe = regexp.MustCompile(`(?im)^\s*(%+\s*)?(no match|not found|no entries found|no data found|no object found|domain not found|nothing found|not registered|the queried object does not exist|status:\s*(free|available))`)

type domainInfo struct {
	expiry     time.Time
	registered time.Time
	hasExpiry  bool
	hasReg     bool
	source     string
	err        string
	unparsed   bool
	transient  bool
	relayed    bool
}

type domainRecord struct {
	Expiry     string `json:"exp,omitempty"`
	Registered string `json:"reg,omitempty"`
	Source     string `json:"src,omitempty"`
	Error      string `json:"err,omitempty"`
	Unparsed   bool   `json:"unparsed,omitempty"`
	Relayed    bool   `json:"relayed,omitempty"`
	FetchedAt  int64  `json:"at"`
	TTLSec     int64  `json:"ttl"`
	InsightDay string `json:"insightDay,omitempty"`
}

type domainFile struct {
	Version int                     `json:"v"`
	Domains map[string]domainRecord `json:"domains"`
}

type whoisServerEntry struct {
	server string
	at     time.Time
}

var domainStore = struct {
	sync.Mutex
	path      string
	loaded    bool
	dirty     bool
	recs      map[string]domainRecord
	bootstrap map[string]string
	bootAt    time.Time
	whoisSrv  map[string]whoisServerEntry
	blocked   map[string]time.Time
}{recs: map[string]domainRecord{}, whoisSrv: map[string]whoisServerEntry{}, blocked: map[string]time.Time{}}

func SetDomainStore(path string) {
	domainStore.Lock()
	domainStore.path = path
	domainStore.loaded = false
	domainStore.Unlock()
}

func domainStoreLoad() {
	if domainStore.loaded {
		return
	}
	domainStore.loaded = true
	if domainStore.path == "" {
		return
	}
	data, err := os.ReadFile(domainStore.path)
	if err != nil {
		return
	}
	var f domainFile
	if json.Unmarshal(data, &f) != nil || f.Domains == nil {
		return
	}
	domainStore.recs = f.Domains
}

func domainStoreSave() {
	domainStore.Lock()
	defer domainStore.Unlock()
	if !domainStore.dirty || domainStore.path == "" {
		return
	}
	data, err := json.Marshal(domainFile{Version: 1, Domains: domainStore.recs})
	if err != nil {
		return
	}
	if atomicfile.Write(domainStore.path, data, 0o644) == nil {
		domainStore.dirty = false
	}
}

func (r domainRecord) info() domainInfo {
	info := domainInfo{source: r.Source, err: r.Error, unparsed: r.Unparsed, relayed: r.Relayed}
	if t, err := time.Parse(time.RFC3339, r.Expiry); err == nil {
		info.expiry, info.hasExpiry = t, true
	}
	if t, err := time.Parse(time.RFC3339, r.Registered); err == nil {
		info.registered, info.hasReg = t, true
	}
	return info
}

func domainKnown(domain string) (domainInfo, bool, bool) {
	domainStore.Lock()
	defer domainStore.Unlock()
	domainStoreLoad()
	r, ok := domainStore.recs[domain]
	if !ok {
		return domainInfo{}, false, false
	}
	fresh := time.Since(time.Unix(r.FetchedAt, 0)) < time.Duration(r.TTLSec)*time.Second
	return r.info(), fresh, true
}

func domainTTL(info domainInfo) time.Duration {
	switch {
	case info.transient:
		return domainTTLTransient
	case info.unparsed:
		return domainTTLUnparsed
	case !info.hasExpiry:
		return domainTTLFar
	}
	left := time.Until(info.expiry)
	switch {
	case left > 60*24*time.Hour:
		return domainTTLFar
	case left > 14*24*time.Hour:
		return domainTTLNear
	}
	return domainTTLClose
}

func domainRemember(domain string, info domainInfo) domainInfo {
	domainStore.Lock()
	defer domainStore.Unlock()
	domainStoreLoad()
	prev := domainStore.recs[domain]
	if info.transient && !info.hasExpiry {
		if p := prev.info(); p.hasExpiry {
			info.expiry, info.hasExpiry, info.source = p.expiry, true, p.source
			if !info.hasReg && p.hasReg {
				info.registered, info.hasReg = p.registered, true
			}
		}
	}
	r := domainRecord{
		Source: info.source, Error: info.err, Unparsed: info.unparsed, Relayed: info.relayed,
		FetchedAt: time.Now().Unix(), TTLSec: int64(domainTTL(info) / time.Second), InsightDay: prev.InsightDay,
	}
	if info.hasExpiry {
		r.Expiry = info.expiry.UTC().Format(time.RFC3339)
	}
	if info.hasReg {
		r.Registered = info.registered.UTC().Format(time.RFC3339)
	}
	domainStore.recs[domain] = r
	domainStore.dirty = true
	return info
}

func domainInsightDue(domain, day string) bool {
	domainStore.Lock()
	defer domainStore.Unlock()
	domainStoreLoad()
	r, ok := domainStore.recs[domain]
	if !ok || r.InsightDay == day {
		return false
	}
	r.InsightDay = day
	domainStore.recs[domain] = r
	domainStore.dirty = true
	return true
}

func directBlocked(kind string) bool {
	domainStore.Lock()
	defer domainStore.Unlock()
	return time.Now().Before(domainStore.blocked[kind])
}

func markBlocked(kind string) {
	domainStore.Lock()
	domainStore.blocked[kind] = time.Now().Add(domainBlockedFor)
	domainStore.Unlock()
}

type lookupRelayFn func(protocol.Lookup) (protocol.LookupResult, error)

type lookupRelayBox struct{ fn lookupRelayFn }

var lookupRelay atomic.Value

func SetLookupRelay(fn lookupRelayFn) { lookupRelay.Store(lookupRelayBox{fn: fn}) }

func relayLookup(req protocol.Lookup) (protocol.LookupResult, error) {
	box, _ := lookupRelay.Load().(lookupRelayBox)
	if box.fn == nil {
		return protocol.LookupResult{}, errNoRelay
	}
	return box.fn(req)
}

func netBlocked(err error) bool {
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return true
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "dial" {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "tls:") || strings.Contains(s, "x509:")
}

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
		info, fresh, _ := domainKnown(domain)
		if !fresh {
			info = domainRemember(domain, lookupDomain(client, domain, timeout))
		}
		if !info.hasExpiry {
			failures = append(failures, domain+": "+info.err)
			continue
		}
		days := info.expiry.Sub(now).Hours() / 24
		tags := map[string]string{"domain": domain}
		o.Metrics = append(o.Metrics, protocol.MetricPoint{
			Name: "ext.domain.days_left", Value: float64(int(days*10)) / 10, Tags: tags,
		})
		fact := map[string]string{"expiry": info.expiry.UTC().Format("2006-01-02")}
		if info.hasReg {
			age := now.Sub(info.registered).Hours() / 24
			o.Metrics = append(o.Metrics, protocol.MetricPoint{
				Name: "ext.domain.age_days", Value: float64(int(age*10)) / 10, Tags: tags,
			})
			fact["registered"] = info.registered.UTC().Format("2006-01-02")
		}
		payload, err := json.Marshal(fact)
		if err == nil {
			o.InvFacts = append(o.InvFacts, protocol.Fact{Kind: "domain", Key: domain, Payload: string(payload)})
		}
	}
	domainStoreSave()
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

func lookupDomain(client *http.Client, domain string, timeout time.Duration) domainInfo {
	tld := tldOf(domain)
	var info domainInfo
	status, body, err, relayed := rdapQuery(client, domain, tld)
	info.relayed = relayed
	tryWhois := false
	switch {
	case err == nil:
		switch {
		case status == http.StatusOK:
			var doc struct {
				Events []rdapEvent `json:"events"`
			}
			if json.Unmarshal(body, &doc) == nil {
				if t, e := rdapEventDate(doc.Events, "expiration"); e == nil {
					info.expiry, info.hasExpiry, info.source = t, true, "rdap"
				}
				if t, e := rdapEventDate(doc.Events, "registration"); e == nil {
					info.registered, info.hasReg = t, true
				}
			}
			if info.hasExpiry {
				return info
			}
			info.err = "rdap answer carries no expiration date"
			tryWhois = true
		case status == http.StatusNotFound:
			info.err = "domain not found at the registry"
			return info
		case status == http.StatusTooManyRequests || status == http.StatusForbidden || status >= 500:
			info.err = "rdap answered " + strconv.Itoa(status)
			info.transient = true
			return info
		default:
			info.err = "rdap answered " + strconv.Itoa(status)
			tryWhois = true
		}
	case errors.Is(err, errNoRdap):
		tryWhois = true
	default:
		info.err = "rdap unreachable: " + err.Error()
		info.transient = true
		return info
	}
	if !tryWhois {
		return info
	}
	raw, err, wrel := whoisQuery(domain, tld, timeout)
	info.relayed = info.relayed || wrel
	switch {
	case err == nil:
		applyWhois(&info, raw)
	case errors.Is(err, errNoWhois):
		if info.err == "" {
			info.err = "the registry publishes no expiry date"
		}
	default:
		info.err = "whois unreachable: " + err.Error()
		info.transient = true
	}
	return info
}

func rdapQuery(client *http.Client, domain, tld string) (int, []byte, error, bool) {
	if !directBlocked("rdap") {
		base, err := rdapBase(client, tld)
		switch {
		case err == nil:
			status, body, gerr := rdapGet(client, base+"domain/"+domain)
			if gerr == nil {
				return status, body, nil, false
			}
			if !netBlocked(gerr) {
				return 0, nil, gerr, false
			}
			markBlocked("rdap")
		case errors.Is(err, errNoRdap):
			return 0, nil, err, false
		case netBlocked(err):
			markBlocked("rdap")
		default:
			return 0, nil, err, false
		}
	}
	res, err := relayLookup(protocol.Lookup{Kind: "rdap", Domain: domain})
	if err != nil {
		return 0, nil, err, true
	}
	if res.Error != "" {
		if strings.Contains(res.Error, "no rdap service") {
			return 0, nil, errNoRdap, true
		}
		return 0, nil, errors.New(res.Error), true
	}
	return res.Status, []byte(res.Body), nil, true
}

func rdapGet(client *http.Client, url string) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	req.Header.Set("User-Agent", probeUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, rdapReadMax))
	resp.Body.Close()
	return resp.StatusCode, body, nil
}

type rdapEvent struct {
	EventAction string `json:"eventAction"`
	EventDate   string `json:"eventDate"`
}

func rdapEventDate(events []rdapEvent, action string) (time.Time, error) {
	for _, e := range events {
		if e.EventAction != action {
			continue
		}
		if t, err := time.Parse(time.RFC3339, e.EventDate); err == nil {
			return t, nil
		}
	}
	return time.Time{}, errNoExpiry
}

func rdapBase(client *http.Client, tld string) (string, error) {
	domainStore.Lock()
	m, fresh := domainStore.bootstrap, time.Since(domainStore.bootAt) < 24*time.Hour
	domainStore.Unlock()
	if m == nil || !fresh {
		fetched, err := fetchRdapBootstrap(client)
		if err != nil {
			if m == nil {
				return "", err
			}
		} else {
			m = fetched
			domainStore.Lock()
			domainStore.bootstrap, domainStore.bootAt = m, time.Now()
			domainStore.Unlock()
		}
	}
	base, ok := m[tld]
	if !ok {
		return "", errNoRdap
	}
	return base, nil
}

func fetchRdapBootstrap(client *http.Client) (map[string]string, error) {
	status, body, err := rdapGet(client, rdapBootstrapURL)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, errors.New("rdap bootstrap answered " + strconv.Itoa(status))
	}
	var boot struct {
		Services [][2][]string `json:"services"`
	}
	if err := json.Unmarshal(body, &boot); err != nil {
		return nil, err
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
	return m, nil
}

func whoisQuery(domain, tld string, timeout time.Duration) (string, error, bool) {
	query := domain + whoisQuerySuffix[tld]
	if !directBlocked("whois") {
		server, err := whoisServerFor(tld, timeout)
		switch {
		case err == nil && server == "":
			return "", errNoWhois, false
		case err == nil:
			raw, qerr := whoisRaw(server, query, timeout)
			if qerr == nil {
				return raw, nil, false
			}
			if !netBlocked(qerr) {
				return "", qerr, false
			}
			markBlocked("whois")
		case netBlocked(err):
			markBlocked("whois")
		default:
			return "", err, false
		}
	}
	res, err := relayLookup(protocol.Lookup{Kind: "whois", Domain: domain, Query: query})
	if err != nil {
		return "", err, true
	}
	if res.Error != "" {
		if strings.Contains(res.Error, "no whois server") {
			return "", errNoWhois, true
		}
		return "", errors.New(res.Error), true
	}
	return res.Body, nil, true
}

func whoisServerFor(tld string, timeout time.Duration) (string, error) {
	domainStore.Lock()
	e, ok := domainStore.whoisSrv[tld]
	domainStore.Unlock()
	if ok && time.Since(e.at) < whoisServerTTL {
		return e.server, nil
	}
	raw, err := whoisRaw("whois.iana.org", tld, timeout)
	if err != nil {
		if ok {
			return e.server, nil
		}
		return "", err
	}
	server := strings.ToLower(extractWhoisField(raw, "whois"))
	domainStore.Lock()
	domainStore.whoisSrv[tld] = whoisServerEntry{server: server, at: time.Now()}
	domainStore.Unlock()
	return server, nil
}

func whoisRaw(server, query string, timeout time.Duration) (string, error) {
	conn, err := net.DialTimeout("tcp", server+":43", timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(query + "\r\n")); err != nil {
		return "", err
	}
	out, err := io.ReadAll(io.LimitReader(conn, whoisReadMax))
	if err != nil && len(out) == 0 {
		return "", err
	}
	return string(out), nil
}

func applyWhois(info *domainInfo, raw string) {
	if whoisNotFoundRe.MatchString(raw) {
		info.err = "domain not found at the registry"
		return
	}
	if whoisRateLimitRe.MatchString(raw) && !whoisLooksLikeRecord(raw) {
		info.err = "whois rate-limited"
		info.transient = true
		return
	}
	fields := whoisFields(raw)
	if v, ok := whoisField(fields, whoisCreatedKeys); ok {
		if t, sentinel, err := parseWhoisDate(v); err == nil && !sentinel {
			info.registered, info.hasReg = t, true
		}
	}
	v, ok := whoisField(fields, whoisExpiryKeys)
	switch {
	case !ok && whoisLooksLikeRecord(raw):
		info.unparsed = true
		info.err = "no expiry field in the registry answer"
		return
	case !ok:
		info.err = "empty registry answer"
		return
	}
	t, sentinel, err := parseWhoisDate(v)
	switch {
	case err == nil && sentinel:
		info.err = "the registry reports no expiry for this domain"
	case err == nil:
		info.expiry, info.hasExpiry, info.source, info.err = t, true, "whois", ""
	default:
		info.unparsed = true
		info.err = "expiry date format not recognized: " + v
	}
}

func whoisLooksLikeRecord(raw string) bool {
	_, ok := whoisField(whoisFields(raw), whoisRecordKeys)
	return ok
}

func whoisFields(raw string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ">>>") || strings.HasPrefix(line, "--") {
			continue
		}
		var key, val string
		if strings.HasPrefix(line, "[") {
			end := strings.IndexByte(line, ']')
			if end < 0 {
				continue
			}
			key, val = line[1:end], line[end+1:]
		} else {
			k, v, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			key, val = k, v
		}
		nk := normWhoisKey(key)
		if nk == "" {
			continue
		}
		val = strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(val), "."))
		if val == "" {
			continue
		}
		if _, dup := out[nk]; !dup {
			out[nk] = val
		}
	}
	return out
}

func whoisField(fields map[string]string, keys []string) (string, bool) {
	for _, k := range keys {
		if v, ok := fields[k]; ok {
			return v, true
		}
	}
	return "", false
}

func normWhoisKey(k string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(k) {
		if c >= 'a' && c <= 'z' {
			b.WriteRune(c)
		}
	}
	return b.String()
}

func parseWhoisDate(raw string) (time.Time, bool, error) {
	v := strings.TrimSpace(raw)
	if i := strings.IndexByte(v, '('); i > 0 {
		v = strings.TrimSpace(v[:i])
	}
	v = strings.TrimRight(strings.Join(strings.Fields(v), " "), ".")
	switch strings.ToLower(v) {
	case "", "never", "n/a", "none", "-", "not applicable", "null":
		return time.Time{}, true, nil
	}
	candidates := []string{v}
	if f := strings.Fields(v); len(f) > 1 {
		candidates = append(candidates, f[0], strings.Join(f[:2], " "))
	}
	for _, c := range candidates {
		for _, layout := range whoisLayouts {
			t, err := time.Parse(layout, c)
			if err != nil {
				continue
			}
			if t.Year() >= 9000 {
				return time.Time{}, true, nil
			}
			return t.UTC(), false, nil
		}
	}
	return time.Time{}, false, errors.New("unrecognized date: " + raw)
}

func parseWhoisExpiry(raw string) (time.Time, error) {
	v, ok := whoisField(whoisFields(raw), whoisExpiryKeys)
	if !ok {
		return time.Time{}, errNoExpiry
	}
	t, sentinel, err := parseWhoisDate(v)
	if err != nil || sentinel {
		return time.Time{}, errNoExpiry
	}
	return t, nil
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

func tldOf(domain string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSuffix(domain, ".")), ".")
	return parts[len(parts)-1]
}

func domainScanNotes(infos map[string]domainInfo) (string, string) {
	relayed := ""
	var unparsed []string
	for reg, info := range infos {
		if info.relayed {
			relayed = "on"
		}
		if info.unparsed {
			unparsed = append(unparsed, reg)
		}
	}
	sort.Strings(unparsed)
	return relayed, strings.Join(unparsed, ",")
}

type domainErr string

func (e domainErr) Error() string { return string(e) }

const (
	errNoExpiry domainErr = "expiry date not found"
	errNoRdap   domainErr = "tld has no rdap service"
	errNoWhois  domainErr = "tld has no whois server"
	errNoRelay  domainErr = "lookup relay unavailable"
)
