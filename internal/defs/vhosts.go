package defs

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
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

	// the config dump + statement parse over hundreds of vhosts is the expensive
	// part of the sweep - reuse the parsed list until the config tree changes
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
			if logs := apacheAccessLogs(p.Command); len(logs) > 0 {
				if o.Facts == nil {
					o.Facts = map[string]string{}
				}
				o.Facts["accessLog"] = strings.Join(logs, ",")
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
	}
	o.Check.Status = "ok"

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

	// pace the probes across the interval instead of a burst: a portfolio of hundreds
	// of WordPress sites gets a steady trickle, not a php-fpm wave every cycle
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
	for i, h := range hosts {
		r := results[i]
		key := fmt.Sprintf("%s:%d", h.Name, h.Port)
		payload, _ := json.Marshal(map[string]any{"service": service, "port": h.Port, "ssl": h.SSL || r.hasSSL})
		o.InvFacts = append(o.InvFacts, protocol.Fact{Kind: "vhost", Key: key, Payload: string(payload)})
		if !probed[i] {
			continue
		}
		o.Extra = append(o.Extra, r.check)

		tags := map[string]string{"vhost": h.Name, "port": strconv.Itoa(h.Port)}
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

// configTreeSig fingerprints a config tree by walking file names, sizes and
// mtimes - cheap stat-only pass, no content reads
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

// window returns the positions (into the primaries list) to probe this cycle:
// everything when the portfolio fits the budget, otherwise a rotating slice so
// every site still gets probed, just at a proportionally longer effective interval
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

func apacheAccessLogs(cmd string) []string {
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
		for _, m := range apacheCustomLogRe.FindAllSubmatch(data, -1) {
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
)

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
