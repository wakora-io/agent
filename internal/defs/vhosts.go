package defs

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"wakora.io/agent/internal/protocol"
)

const probeUserAgent = "Wakora-Monitor/1.0 (+https://wakora.io)"

type vhost struct {
	Name    string
	Port    int
	SSL     bool
	Primary bool
}

func runVhosts(o *Outcome, service string, p protocol.Probe, timeout time.Duration) {
	o.Check.Target = p.Command + " vhosts"
	if p.Command == "" || strings.ContainsAny(p.Command, "/\\") || !execAllowlist[p.Command] {
		o.Check.Status = "fail"
		o.Check.Error = "command not in allow-list"
		return
	}
	var args []string
	var parse func([]byte) []vhost
	switch p.Command {
	case "nginx":
		args = []string{"-T"}
		parse = parseNginxVhosts
	case "apache2ctl", "httpd":
		args = []string{"-S"}
		parse = parseApacheVhosts
	default:
		o.Check.Status = "fail"
		o.Check.Error = "no vhost support for " + p.Command
		return
	}
	path, err := exec.LookPath(p.Command)
	if err != nil {
		o.Check.Status = "fail"
		o.Check.Error = err.Error()
		return
	}

	sig := ""
	if p.Command == "nginx" {
		sig = configTreeSig("/etc/nginx")
	}
	hosts, cached := vhostParseCache.get(service, sig)
	if !cached {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		out, err := exec.CommandContext(ctx, path, args...).CombinedOutput()
		if len(out) > 2<<20 {
			out = out[:2<<20]
		}
		if ctx.Err() != nil {
			o.Check.Status = "fail"
			o.Check.Error = "timeout"
			return
		}
		if err != nil {
			o.Check.Status = "fail"
			msg := strings.TrimSpace(string(out))
			if msg == "" {
				msg = err.Error()
			}
			if len(msg) > 200 {
				msg = msg[:200]
			}
			o.Check.Error = msg
			return
		}

		if p.Command != "nginx" {
			if o.Facts == nil {
				o.Facts = map[string]string{}
			}
			if logs := apacheLogs(p.Command, apacheCustomLogRe); len(logs) > 0 {
				o.Facts["accessLog"] = strings.Join(logs, ",")
			}
			if logs := apacheLogs(p.Command, apacheErrorLogRe); len(logs) > 0 {
				o.Facts["errorLog"] = strings.Join(logs, ",")
			}
		}

		hosts = parse(out)
		sort.Slice(hosts, func(i, j int) bool {
			if hosts[i].Name != hosts[j].Name {
				return hosts[i].Name < hosts[j].Name
			}
			return hosts[i].Port < hosts[j].Port
		})
		vhostParseCache.put(service, sig, hosts)
		if p.Command == "nginx" {
			s := scanStickyPools(out)
			if prev, ok := stickyPoolsCache.Load(service); s != "" && (!ok || prev.(string) != s) {
				detail, _ := json.Marshal(map[string]string{"type": "sticky_pools", "pools": s})
				o.Events = append(o.Events, protocol.AgentEvent{Kind: "insight", Detail: string(detail)})
			}
			stickyPoolsCache.Store(service, s)
			vhostPoolsCache.Store(service, scanVhostPools(out))
		} else {
			apacheRootsCache.Store(service, apacheVhostRoots(out))
		}
	}
	o.Check.Status = "ok"
	if p.Command == "nginx" {
		if v, ok := stickyPoolsCache.Load(service); ok {
			if o.Facts == nil {
				o.Facts = map[string]string{}
			}
			o.Facts["stickyPools"] = v.(string)
		}
	}

	var primaries []int
	for i, h := range hosts {
		if h.Primary {
			primaries = append(primaries, i)
		}
	}
	window := vhostCursors.window(service, len(primaries), vhostBudget)
	if len(primaries) > vhostBudget {
		o.Check.Target = fmt.Sprintf("%s vhosts (%d of %d per cycle)", p.Command, len(window), len(primaries))
	}
	probed := map[int]bool{}
	for _, wi := range window {
		probed[primaries[wi]] = true
	}

	spacing := time.Duration(0)
	if n := len(window); n > 0 && p.IntervalSec > 0 {
		spacing = time.Duration(p.IntervalSec) * time.Second * 3 / 4 / time.Duration(n)
		if spacing > vhostMaxSpacing {
			spacing = vhostMaxSpacing
		}
	}

	results := make([]vhostResult, len(hosts))
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	started := 0
	for i, h := range hosts {
		if !probed[i] {
			continue
		}
		if started > 0 && spacing > 0 {
			time.Sleep(spacing)
		}
		started++
		wg.Add(1)
		go func(i int, h vhost) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = probeVhost(service, h, timeout)
		}(i, h)
	}
	wg.Wait()

	dnsNames := make([]string, 0, len(window))
	seenName := map[string]bool{}
	for _, pi := range primaries {
		if !probed[pi] {
			continue
		}
		if n := dnsProbeName(hosts[pi].Name); n != "" && !seenName[n] {
			seenName[n] = true
			dnsNames = append(dnsNames, n)
		}
	}
	dnsAlive := vhostDNSSweep(dnsNames, 3*time.Second)
	localAddrs := hostAddrSet()
	domInfo := vhostDomainScan(dnsNames, 5*time.Second)

	dnsEmitted := map[string]bool{}
	domEmitted := map[string]bool{}
	deadConfirmed := map[string]bool{}
	for name, res := range dnsAlive {
		deadConfirmed[name] = dnsConfirmedDead(name, res.alive)
	}
	poolMinor := map[string]fpmPoolInfo{}
	if p.Command == "nginx" {
		poolMinor = vhostPoolMinorMap(service)
	}
	apacheRoots := map[string]string{}
	if p.Command != "nginx" {
		if v, ok := apacheRootsCache.Load(service); ok {
			apacheRoots, _ = v.(map[string]string)
		}
	}
	for i, h := range hosts {
		r := results[i]
		key := fmt.Sprintf("%s:%d", h.Name, h.Port)
		pm := map[string]any{"service": service, "port": h.Port, "ssl": h.SSL || r.hasSSL}
		if info, ok := poolMinor[h.Name]; ok {
			if info.Minor != "" {
				pm["php"] = info.Minor
			}
			if info.Prepend != "" && !strings.Contains(info.Prepend, "/wakora/") {
				pm["prependOverride"] = info.Prepend
			}
			if info.WP {
				pm["wp"] = 1
			}
		}
		if root, ok := apacheRoots[h.Name]; ok && wpAt(root) {
			pm["wp"] = 1
		}
		payload, _ := json.Marshal(pm)
		o.InvFacts = append(o.InvFacts, protocol.Fact{Kind: "vhost", Key: key, Payload: string(payload)})
		if !probed[i] {
			continue
		}

		tags := map[string]string{"vhost": h.Name, "port": strconv.Itoa(h.Port)}
		if res, known := dnsAlive[dnsProbeName(h.Name)]; known {
			confirmedDead := deadConfirmed[dnsProbeName(h.Name)]
			if !res.alive && confirmedDead {
				if r.check.Error != "" {
					r.check.Error += "; "
				}
				r.check.Error += "domain does not resolve (NXDOMAIN)"
			}
			if !dnsEmitted[h.Name] {
				dnsEmitted[h.Name] = true
				// a first, unconfirmed NXDOMAIN emits NOTHING: a transient resolver
				// flap must not open (or resolve) incidents
				if res.alive || confirmedDead {
					v := 0.0
					if res.alive {
						v = 1
					}
					o.Metrics = append(o.Metrics, protocol.MetricPoint{
						Name: "svc." + service + ".vhost.dns_ok", Value: v,
						Tags: map[string]string{"vhost": h.Name},
					})
				}
				if off, ok := vhostOffloaded(res, localAddrs); ok {
					ov := 0.0
					if off {
						ov = 1
					}
					o.Metrics = append(o.Metrics, protocol.MetricPoint{
						Name: "svc." + service + ".vhost.offloaded", Value: ov,
						Tags: map[string]string{"vhost": h.Name},
					})
				}
			}
		}
		if reg := vhostRegistrable(h.Name); reg != "" && !domEmitted[reg] {
			if info, ok := domInfo[reg]; ok && (info.hasReg || info.hasExpiry) {
				domEmitted[reg] = true
				if info.hasReg {
					age := time.Since(info.registered).Hours() / 24
					o.Metrics = append(o.Metrics, protocol.MetricPoint{
						Name: "svc." + service + ".vhost.domain_age_days", Value: float64(int(age*10)) / 10,
						Tags: map[string]string{"vhost": reg},
					})
				}
				// negative = the registration lapsed but the zone still answers: the
				// grace window where the client can still save the domain
				if info.hasExpiry {
					left := time.Until(info.expiry).Hours() / 24
					o.Metrics = append(o.Metrics, protocol.MetricPoint{
						Name: "svc." + service + ".vhost.domain_days_left", Value: float64(int(left*10)) / 10,
						Tags: map[string]string{"vhost": reg},
					})
				}
			}
		}
		o.Extra = append(o.Extra, r.check)

		if r.check.Status == "ok" {
			o.Metrics = append(o.Metrics, protocol.MetricPoint{
				Name: "svc." + service + ".vhost.latency_ms", Value: r.check.LatencyMs, Tags: tags,
			})
		}
		if r.hasSSL {
			trusted := 0.0
			if r.trusted {
				trusted = 1
			}
			o.Metrics = append(o.Metrics,
				protocol.MetricPoint{Name: "svc." + service + ".vhost.ssl_days_left", Value: r.sslDays, Tags: tags},
				protocol.MetricPoint{Name: "svc." + service + ".vhost.ssl_trusted", Value: trusted, Tags: tags},
			)
		}
	}
}

func dnsProbeName(raw string) string {
	n := strings.ToLower(strings.Trim(raw, "."))
	if n == "" || n == "_" || n == "localhost" || !strings.Contains(n, ".") {
		return ""
	}
	if net.ParseIP(n) != nil {
		return ""
	}
	for _, c := range n {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
			return ""
		}
	}
	for _, suffix := range []string{".local", ".localhost", ".internal", ".lan", ".home", ".test", ".invalid"} {
		if strings.HasSuffix(n, suffix) {
			return ""
		}
	}
	return n
}

var vhostLookupHost = func(ctx context.Context, name string) ([]string, error) {
	// rooted lookup: the trailing dot keeps the resolver from appending
	// resolv.conf search suffixes - found live on example, where a DEAD .org
	// "resolved" through search example.lab into a wildcard lab address
	return net.DefaultResolver.LookupHost(ctx, name+".")
}

type dnsSweepResult struct {
	alive bool
	ips   []string
}

// nxdomain debounce: a flapping resolver (rotating nameservers with different
// views) must not paint a live domain dead or ring twice - the verdict flips to
// dead only on the SECOND consecutive NXDOMAIN sweep
var dnsSuspect = struct {
	sync.Mutex
	m map[string]int
}{m: map[string]int{}}

// dnsConfirmedDead counts consecutive NXDOMAIN sweeps for a name and reports
// whether the death is confirmed; a live sweep resets the counter.
func dnsConfirmedDead(name string, alive bool) bool {
	dnsSuspect.Lock()
	defer dnsSuspect.Unlock()
	if alive {
		delete(dnsSuspect.m, name)
		return false
	}
	dnsSuspect.m[name]++
	return dnsSuspect.m[name] >= 2
}

func vhostDNSSweep(names []string, perLookup time.Duration) map[string]dnsSweepResult {
	out := map[string]dnsSweepResult{}
	if len(names) == 0 {
		return out
	}
	var mu sync.Mutex
	var misses atomic.Int32
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, name := range names {
		if misses.Load() >= 5 {
			break
		}
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if misses.Load() >= 5 {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), perLookup)
			defer cancel()
			ips, err := vhostLookupHost(ctx, name)
			if err == nil {
				misses.Store(0)
				mu.Lock()
				out[name] = dnsSweepResult{alive: true, ips: ips}
				mu.Unlock()
				return
			}
			var de *net.DNSError
			if errors.As(err, &de) && de.IsNotFound {
				misses.Store(0)
				mu.Lock()
				out[name] = dnsSweepResult{alive: false}
				mu.Unlock()
				return
			}
			misses.Add(1)
		}(name)
	}
	wg.Wait()
	return out
}

var publicIP atomic.Value

func SetPublicIP(ip string) {
	if net.ParseIP(ip) != nil {
		publicIP.Store(ip)
	}
}

func hostAddrSet() map[string]bool {
	set := map[string]bool{}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				set[ipn.IP.String()] = true
			}
		}
	}
	if p, ok := publicIP.Load().(string); ok && p != "" {
		set[p] = true
	}
	return set
}

func vhostOffloaded(res dnsSweepResult, local map[string]bool) (bool, bool) {
	if !res.alive || len(res.ips) == 0 {
		return false, false
	}
	if p, ok := publicIP.Load().(string); !ok || p == "" {
		return false, false
	}
	for _, ip := range res.ips {
		if p := net.ParseIP(ip); p != nil && (p.IsLoopback() || local[p.String()]) {
			return false, true
		}
	}
	return true, true
}

var ccSLD = map[string]bool{
	"co.uk": true, "org.uk": true, "me.uk": true, "ac.uk": true, "gov.uk": true,
	"com.au": true, "net.au": true, "org.au": true, "co.nz": true, "net.nz": true,
	"com.br": true, "net.br": true, "co.jp": true, "or.jp": true, "ne.jp": true,
	"com.tr": true, "com.pl": true, "net.pl": true, "org.pl": true, "com.ua": true,
	"co.za": true, "com.mx": true, "com.ar": true, "com.cn": true, "com.hk": true,
	"co.in": true, "co.kr": true, "com.sg": true, "com.my": true, "co.id": true,
}

func vhostRegistrable(name string) string {
	n := dnsProbeName(strings.TrimPrefix(name, "*."))
	if n == "" {
		return ""
	}
	parts := strings.Split(n, ".")
	if len(parts) < 2 {
		return ""
	}
	last2 := strings.Join(parts[len(parts)-2:], ".")
	if len(parts) >= 3 && ccSLD[last2] {
		return strings.Join(parts[len(parts)-3:], ".")
	}
	return last2
}

const vhostDomainBudget = 10

func vhostDomainScan(names []string, timeout time.Duration) map[string]domainInfo {
	uniq := map[string]bool{}
	for _, n := range names {
		if reg := vhostRegistrable(n); reg != "" {
			uniq[reg] = true
		}
	}
	out := map[string]domainInfo{}
	client := &http.Client{Timeout: timeout}
	budget := vhostDomainBudget
	for reg := range uniq {
		if info, ok := domainCached(reg); ok {
			out[reg] = info
			continue
		}
		if budget <= 0 {
			continue
		}
		budget--
		out[reg] = rdapLookupCached(client, reg)
		time.Sleep(300 * time.Millisecond)
	}
	return out
}

func rdapLookupCached(client *http.Client, domain string) domainInfo {
	if info, ok := domainCached(domain); ok {
		return info
	}
	info := rdapLookup(client, domain)
	domainCache.Lock()
	domainCache.info[domain] = info
	domainCache.fetchedAt[domain] = time.Now()
	domainCache.Unlock()
	return info
}

const (
	vhostBudget     = 100
	vhostMaxSpacing = 5 * time.Second
	vhostCacheMax   = 30 * time.Minute
)

type vhostParseEntry struct {
	sig   string
	when  time.Time
	hosts []vhost
}

type vhostParseCacheSet struct {
	mu      sync.Mutex
	entries map[string]vhostParseEntry
}

var vhostParseCache = &vhostParseCacheSet{entries: map[string]vhostParseEntry{}}

func (c *vhostParseCacheSet) get(service, sig string) ([]vhost, bool) {
	if sig == "" {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[service]
	if !ok || e.sig != sig || time.Since(e.when) > vhostCacheMax {
		return nil, false
	}
	return e.hosts, true
}

func (c *vhostParseCacheSet) put(service, sig string, hosts []vhost) {
	if sig == "" {
		return
	}
	c.mu.Lock()
	c.entries[service] = vhostParseEntry{sig: sig, when: time.Now(), hosts: hosts}
	c.mu.Unlock()
}

func configTreeSig(root string) string {
	h := sha256.New()
	found := false
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		found = true
		fmt.Fprintf(h, "%s|%d|%d\n", path, info.Size(), info.ModTime().UnixNano())
		return nil
	})
	if !found {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

type vhostCursorSet struct {
	mu      sync.Mutex
	cursors map[string]int
}

var vhostCursors = &vhostCursorSet{cursors: map[string]int{}}

func (s *vhostCursorSet) window(service string, n, budget int) []int {
	if n <= 0 {
		return nil
	}
	if n <= budget {
		out := make([]int, n)
		for i := range out {
			out[i] = i
		}
		return out
	}
	s.mu.Lock()
	start := s.cursors[service] % n
	s.cursors[service] = (start + budget) % n
	s.mu.Unlock()
	out := make([]int, 0, budget)
	for i := 0; i < budget; i++ {
		out = append(out, (start+i)%n)
	}
	return out
}

type vhostResult struct {
	check   protocol.CheckResult
	sslDays float64
	hasSSL  bool
	trusted bool
}

func probeVhost(service string, h vhost, timeout time.Duration) vhostResult {
	hostHeader := h.Name
	if hostHeader == "_" || hostHeader == "" {
		hostHeader = "localhost"
	}
	scheme := "http"
	if h.SSL || h.Port == 443 {
		scheme = "https"
	} else if h.Port != 80 && sniffTLS(h.Port, hostHeader, timeout) {
		scheme = "https"
	}
	r := vhostResult{check: protocol.CheckResult{
		CheckID:   service + "/vhost/" + fmt.Sprintf("%s:%d", h.Name, h.Port),
		Kind:      "http",
		Target:    fmt.Sprintf("%s://%s:%d/", scheme, hostHeader, h.Port),
		Timestamp: time.Now().Unix(),
	}}
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s://127.0.0.1:%d/", scheme, h.Port), nil)
	if err != nil {
		r.check.Status = "fail"
		r.check.Error = err.Error()
		return r
	}
	req.Host = hostHeader
	req.Header.Set("User-Agent", probeUserAgent)
	tr := &http.Transport{DisableKeepAlives: true}
	if scheme == "https" {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, ServerName: hostHeader}
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	start := time.Now()
	resp, err := client.Do(req)
	r.check.LatencyMs = float64(time.Since(start).Microseconds()) / 1000
	if err != nil {
		r.check.Status = "fail"
		r.check.Error = err.Error()
		return r
	}
	defer resp.Body.Close()

	var notes []string
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		r.hasSSL = true
		cert := resp.TLS.PeerCertificates[0]
		r.sslDays = time.Until(cert.NotAfter).Hours() / 24
		r.trusted = true
		if time.Now().After(cert.NotAfter) {
			r.trusted = false
			notes = append(notes, "certificate expired")
		} else if note := verifyCert(resp.TLS.PeerCertificates); note != "" {
			r.trusted = false
			notes = append(notes, note)
		}
	}
	if resp.StatusCode >= 500 {
		r.check.Status = "fail"
		notes = append([]string{"status " + strconv.Itoa(resp.StatusCode)}, notes...)
	} else {
		r.check.Status = "ok"
		if resp.StatusCode >= 400 {
			notes = append([]string{"status " + strconv.Itoa(resp.StatusCode)}, notes...)
		}
	}
	r.check.Error = strings.Join(notes, "; ")
	return r
}

func sniffTLS(port int, serverName string, timeout time.Duration) bool {
	d := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(d, "tcp", fmt.Sprintf("127.0.0.1:%d", port), &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
	})
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func verifyCert(chain []*x509.Certificate) string {
	leaf := chain[0]
	if len(chain) == 1 && leaf.Issuer.String() == leaf.Subject.String() {
		return "self-signed certificate"
	}
	opts := x509.VerifyOptions{Intermediates: x509.NewCertPool()}
	for _, c := range chain[1:] {
		opts.Intermediates.AddCert(c)
	}
	if _, err := leaf.Verify(opts); err != nil {
		return "untrusted certificate"
	}
	return ""
}

var apacheCustomLogRe = regexp.MustCompile(`(?mi)^\s*CustomLog\s+"?([^"\s]+)`)
var apacheErrorLogRe = regexp.MustCompile(`(?mi)^\s*ErrorLog\s+"?([^"\s]+)`)

func apacheLogs(cmd string, re *regexp.Regexp) []string {
	confDir := "/etc/apache2"
	logDir := "/var/log/apache2"
	if cmd == "httpd" {
		confDir = "/etc/httpd"
		logDir = "/var/log/httpd"
	}
	if v := apacheEnvLogDir(confDir + "/envvars"); v != "" {
		logDir = v
	}
	seen := map[string]bool{}
	var out []string
	_ = filepath.WalkDir(confDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".conf") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		for _, m := range re.FindAllSubmatch(data, -1) {
			p := resolveApachePath(string(m[1]), logDir)
			if p == "" || seen[p] {
				continue
			}
			seen[p] = true
			out = append(out, p)
		}
		return nil
	})
	return out
}

func resolveApachePath(raw, logDir string) string {
	raw = strings.ReplaceAll(raw, "${APACHE_LOG_DIR}", logDir)
	raw = strings.ReplaceAll(raw, "$APACHE_LOG_DIR", logDir)
	if strings.Contains(raw, "$") || raw == "" {
		return ""
	}
	if !strings.HasPrefix(raw, "/") {
		raw = logDir + "/" + raw
	}
	return raw
}

func apacheEnvLogDir(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	m := regexp.MustCompile(`(?m)APACHE_LOG_DIR=(\S+)`).FindSubmatch(data)
	if len(m) < 2 {
		return ""
	}
	v := strings.Trim(string(m[1]), `"`)
	if i := strings.IndexByte(v, '$'); i >= 0 {
		v = v[:i]
	}
	return v
}

var nginxServerRe = regexp.MustCompile(`^server\s*(\{|$)`)

var stickyPoolsCache sync.Map

var vhostPoolsCache sync.Map

type vhostScanInfo struct {
	pass string
	root string
}

func scanVhostPools(out []byte) map[string]vhostScanInfo {
	byName := map[string]vhostScanInfo{}
	depth := 0
	inServer := false
	braceOpen := false
	entryDepth := 0
	var names []string
	pass := ""
	root := ""

	flush := func() {
		if pass != "" || root != "" {
			for _, n := range names {
				if _, ok := byName[n]; !ok {
					byName[n] = vhostScanInfo{pass: pass, root: root}
				}
			}
		}
		names, pass, root = nil, "", ""
	}

	for _, raw := range strings.Split(string(out), "\n") {
		line := raw
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if !inServer && nginxServerRe.MatchString(trimmed) {
			inServer = true
			braceOpen = false
			entryDepth = depth
		}
		if inServer {
			stmts, _ := splitNginxStatements(trimmed)
			for _, st := range stmts {
				f := strings.Fields(st)
				if len(f) < 2 {
					continue
				}
				switch f[0] {
				case "server_name":
					names = append(names, f[1:]...)
				case "fastcgi_pass":
					if pass == "" {
						pass = f[1]
					}
				case "root":
					if root == "" {
						root = strings.TrimSuffix(f[1], ";")
					}
				}
			}
			if strings.IndexByte(trimmed, '{') >= 0 {
				braceOpen = true
			}
		}
		depth += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
		if inServer && braceOpen && depth <= entryDepth {
			flush()
			inServer = false
		}
	}
	return byName
}

var fpmListenRe = regexp.MustCompile(`(?m)^\s*listen\s*=\s*(\S+)`)
var fpmPrependRe = regexp.MustCompile(`(?m)^\s*php_(?:admin_)?value\[auto_prepend_file\]\s*=\s*(\S*)`)
var fpmDebMinorRe = regexp.MustCompile(`/php/(\d+\.\d+)/`)
var fpmRemiMinorRe = regexp.MustCompile(`/php(\d)(\d)/`)

type fpmPoolInfo struct {
	Minor   string
	Prepend string
	WP      bool
}

func wpAt(root string) bool {
	if root == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(root, "wp-settings.php"))
	return err == nil
}

func fpmListenPools(globs ...string) map[string]fpmPoolInfo {
	if len(globs) == 0 {
		globs = []string{"/etc/php/*/fpm/pool.d/*.conf", "/etc/opt/remi/php*/php-fpm.d/*.conf"}
	}
	out := map[string]fpmPoolInfo{}
	for _, g := range globs {
		files, _ := filepath.Glob(g)
		for _, f := range files {
			minor := ""
			if m := fpmDebMinorRe.FindStringSubmatch(f); m != nil {
				minor = m[1]
			} else if m := fpmRemiMinorRe.FindStringSubmatch(f); m != nil {
				minor = m[1] + "." + m[2]
			}
			if minor == "" {
				continue
			}
			data, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			info := fpmPoolInfo{Minor: minor}
			if m := fpmPrependRe.FindSubmatch(data); m != nil {
				info.Prepend = strings.TrimSpace(string(m[1]))
				if info.Prepend == "" {
					info.Prepend = "none"
				}
			}
			for _, lm := range fpmListenRe.FindAllSubmatch(data, -1) {
				out[strings.TrimSpace(string(lm[1]))] = info
			}
		}
	}
	return out
}

func vhostPoolMinorMap(service string) map[string]fpmPoolInfo {
	v, ok := vhostPoolsCache.Load(service)
	if !ok {
		return nil
	}
	scanByName, _ := v.(map[string]vhostScanInfo)
	if len(scanByName) == 0 {
		return nil
	}
	listens := fpmListenPools()
	out := map[string]fpmPoolInfo{}
	for name, scan := range scanByName {
		info, matched := listens[strings.TrimPrefix(scan.pass, "unix:")]
		if !matched && scan.root == "" {
			continue
		}
		info.WP = wpAt(scan.root)
		if matched || info.WP {
			out[name] = info
		}
	}
	return out
}

func scanStickyPools(out []byte) string {
	type poolUse struct {
		vhosts []string
		admin  int
	}
	pools := map[string]*poolUse{}
	var order []string
	depth := 0
	inServer := false
	braceOpen := false
	entryDepth := 0
	name := ""
	pass := ""
	admin := false

	flushSrv := func() {
		if pass != "" {
			pl := pools[pass]
			if pl == nil {
				pl = &poolUse{}
				pools[pass] = pl
				order = append(order, pass)
			}
			if name == "" {
				name = "_"
			}
			pl.vhosts = append(pl.vhosts, name)
			if admin {
				pl.admin++
			}
		}
		name, pass, admin = "", "", false
	}

	for _, raw := range strings.Split(string(out), "\n") {
		line := raw
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if !inServer && nginxServerRe.MatchString(trimmed) {
			inServer = true
			braceOpen = false
			entryDepth = depth
		}
		if inServer {
			stmts, _ := splitNginxStatements(trimmed)
			for _, st := range stmts {
				f := strings.Fields(st)
				if len(f) < 2 {
					continue
				}
				switch f[0] {
				case "server_name":
					if name == "" {
						name = f[1]
					}
				case "fastcgi_pass":
					if pass == "" {
						pass = f[1]
					}
				case "fastcgi_param":
					if f[1] == "PHP_ADMIN_VALUE" {
						admin = true
					}
				}
			}
			if strings.IndexByte(trimmed, '{') >= 0 {
				braceOpen = true
			}
		}
		depth += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
		if inServer && braceOpen && depth <= entryDepth {
			flushSrv()
			inServer = false
		}
	}

	var parts []string
	for _, p := range order {
		pl := pools[p]
		if len(pl.vhosts) > 1 && pl.admin > 0 {
			parts = append(parts, fmt.Sprintf("%s shared by %d vhosts, %d set PHP_ADMIN_VALUE (e.g. %s)", p, len(pl.vhosts), pl.admin, pl.vhosts[0]))
		}
	}
	s := strings.Join(parts, "; ")
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

func parseNginxVhosts(out []byte) []vhost {
	var hosts []vhost
	depth := 0
	inServer := false
	braceOpen := false
	entryDepth := 0
	carry := ""
	var names []string
	var listens []vhost

	flush := func() {
		if len(listens) == 0 {
			listens = []vhost{{Port: 80}}
		}
		if len(names) == 0 {
			names = []string{"_"}
		}
		for i, n := range names {
			for _, l := range listens {
				hosts = append(hosts, vhost{Name: n, Port: l.Port, SSL: l.SSL, Primary: i == 0})
			}
		}
		names, listens = nil, nil
	}

	for _, raw := range strings.Split(string(out), "\n") {
		line := raw
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if !inServer && nginxServerRe.MatchString(trimmed) {
			inServer = true
			braceOpen = false
			entryDepth = depth
			carry = ""
		}
		if inServer {
			stmts, tail := splitNginxStatements(carry + " " + trimmed)
			for _, st := range stmts {
				applyNginxDirective(st, &names, &listens)
			}
			carry = ""
			if f := strings.Fields(tail); len(f) > 0 && (f[0] == "server_name" || f[0] == "listen") {
				carry = tail
			}
			if strings.IndexByte(trimmed, '{') >= 0 {
				braceOpen = true
			}
		}
		depth += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
		if inServer && braceOpen && depth <= entryDepth {
			flush()
			inServer = false
			carry = ""
		}
	}
	return dedupeVhosts(hosts)
}

func splitNginxStatements(line string) ([]string, string) {
	var stmts []string
	start := 0
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case ';', '{', '}':
			if s := strings.TrimSpace(line[start:i]); s != "" {
				stmts = append(stmts, s)
			}
			start = i + 1
		}
	}
	return stmts, strings.TrimSpace(line[start:])
}

func applyNginxDirective(stmt string, names *[]string, listens *[]vhost) {
	fields := strings.Fields(stmt)
	if len(fields) < 2 {
		return
	}
	switch fields[0] {
	case "server_name":
		*names = append(*names, fields[1:]...)
	case "listen":
		addr := fields[1]
		if i := strings.LastIndexByte(addr, ':'); i >= 0 {
			addr = addr[i+1:]
		}
		port, err := strconv.Atoi(addr)
		if err != nil || port <= 0 {
			return
		}
		ssl := false
		for _, f := range fields[2:] {
			if f == "ssl" {
				ssl = true
			}
		}
		*listens = append(*listens, vhost{Port: port, SSL: ssl})
	}
}

var (
	apacheHeaderRe  = regexp.MustCompile(`^\*:(\d+)\s+is a NameVirtualHost`)
	apacheSingleRe  = regexp.MustCompile(`^\*:(\d+)\s+(\S+)\s+\(`)
	apacheNameRe    = regexp.MustCompile(`port (\d+) namevhost (\S+)`)
	apacheDefaultRe = regexp.MustCompile(`default server (\S+)`)
	apacheVhFileRe  = regexp.MustCompile(`namevhost (\S+)\s+\(([^:)]+):\d+\)|default server (\S+)\s+\(([^:)]+):\d+\)|^\*:\d+\s+(\S+)\s+\(([^:)]+):\d+\)`)
	apacheDocRootRe = regexp.MustCompile(`(?mi)^\s*DocumentRoot\s+"?([^"\s]+)`)
)

var apacheRootsCache sync.Map

func apacheVhostRoots(out []byte) map[string]string {
	roots := map[string]string{}
	fileRoot := map[string]string{}
	for _, raw := range strings.Split(string(out), "\n") {
		m := apacheVhFileRe.FindStringSubmatch(strings.TrimSpace(raw))
		if m == nil {
			continue
		}
		name, file := "", ""
		switch {
		case m[1] != "":
			name, file = m[1], m[2]
		case m[3] != "":
			name, file = m[3], m[4]
		default:
			name, file = m[5], m[6]
		}
		if name == "" || file == "" {
			continue
		}
		if _, ok := roots[name]; ok {
			continue
		}
		root, cached := fileRoot[file]
		if !cached {
			if data, err := os.ReadFile(file); err == nil {
				if dm := apacheDocRootRe.FindSubmatch(data); dm != nil {
					root = strings.TrimSpace(string(dm[1]))
				}
			}
			fileRoot[file] = root
		}
		if root != "" {
			roots[name] = root
		}
	}
	return roots
}

func parseApacheVhosts(out []byte) []vhost {
	var hosts []vhost
	curPort := 0
	for _, raw := range strings.Split(string(out), "\n") {
		line := strings.TrimSpace(raw)
		if m := apacheHeaderRe.FindStringSubmatch(line); m != nil {
			curPort, _ = strconv.Atoi(m[1])
			continue
		}
		if m := apacheSingleRe.FindStringSubmatch(line); m != nil {
			port, _ := strconv.Atoi(m[1])
			hosts = append(hosts, vhost{Name: m[2], Port: port, SSL: port == 443, Primary: true})
			continue
		}
		if m := apacheNameRe.FindStringSubmatch(line); m != nil {
			port, _ := strconv.Atoi(m[1])
			hosts = append(hosts, vhost{Name: m[2], Port: port, SSL: port == 443, Primary: true})
			continue
		}
		if m := apacheDefaultRe.FindStringSubmatch(line); m != nil && curPort > 0 {
			hosts = append(hosts, vhost{Name: m[1], Port: curPort, SSL: curPort == 443, Primary: true})
		}
	}
	return dedupeVhosts(hosts)
}

func dedupeVhosts(hosts []vhost) []vhost {
	seen := map[string]bool{}
	var out []vhost
	for _, h := range hosts {
		key := fmt.Sprintf("%s:%d", h.Name, h.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, h)
	}
	return out
}
