package defs

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"wakora.io/agent/internal/protocol"
)

type vhost struct {
	Name string
	Port int
	SSL  bool
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
	o.Check.Status = "ok"

	hosts := parse(out)
	sort.Slice(hosts, func(i, j int) bool {
		if hosts[i].Name != hosts[j].Name {
			return hosts[i].Name < hosts[j].Name
		}
		return hosts[i].Port < hosts[j].Port
	})
	for _, h := range hosts {
		key := fmt.Sprintf("%s:%d", h.Name, h.Port)
		payload, _ := json.Marshal(map[string]any{"service": service, "port": h.Port, "ssl": h.SSL})
		o.InvFacts = append(o.InvFacts, protocol.Fact{Kind: "vhost", Key: key, Payload: string(payload)})

		check, sslDays, hasSSL := probeVhost(service, h, timeout)
		o.Extra = append(o.Extra, check)
		tags := map[string]string{"vhost": h.Name, "port": strconv.Itoa(h.Port)}
		if check.Status == "ok" {
			o.Metrics = append(o.Metrics, protocol.MetricPoint{
				Name: "svc." + service + ".vhost.latency_ms", Value: check.LatencyMs, Tags: tags,
			})
		}
		if hasSSL {
			o.Metrics = append(o.Metrics, protocol.MetricPoint{
				Name: "svc." + service + ".vhost.ssl_days_left", Value: sslDays, Tags: tags,
			})
		}
	}
}

func probeVhost(service string, h vhost, timeout time.Duration) (protocol.CheckResult, float64, bool) {
	hostHeader := h.Name
	if hostHeader == "_" || hostHeader == "" {
		hostHeader = "localhost"
	}
	scheme := "http"
	if h.SSL || h.Port == 443 {
		scheme = "https"
	}
	res := protocol.CheckResult{
		CheckID:   service + "/vhost/" + fmt.Sprintf("%s:%d", h.Name, h.Port),
		Kind:      "http",
		Target:    fmt.Sprintf("%s://%s:%d/", scheme, hostHeader, h.Port),
		Timestamp: time.Now().Unix(),
	}
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s://127.0.0.1:%d/", scheme, h.Port), nil)
	if err != nil {
		res.Status = "fail"
		res.Error = err.Error()
		return res, 0, false
	}
	req.Host = hostHeader
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if scheme == "https" {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: hostHeader},
		}
	}
	start := time.Now()
	resp, err := client.Do(req)
	res.LatencyMs = float64(time.Since(start).Microseconds()) / 1000
	if err != nil {
		res.Status = "fail"
		res.Error = err.Error()
		return res, 0, false
	}
	defer resp.Body.Close()

	var sslDays float64
	hasSSL := false
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		sslDays = time.Until(resp.TLS.PeerCertificates[0].NotAfter).Hours() / 24
		hasSSL = true
	}
	if resp.StatusCode >= 500 {
		res.Status = "fail"
		res.Error = "status " + strconv.Itoa(resp.StatusCode)
	} else {
		res.Status = "ok"
		if resp.StatusCode >= 400 {
			res.Error = "status " + strconv.Itoa(resp.StatusCode)
		}
	}
	return res, sslDays, hasSSL
}

var nginxServerRe = regexp.MustCompile(`^server\s*\{?`)

func parseNginxVhosts(out []byte) []vhost {
	var hosts []vhost
	depth := 0
	inServer := false
	entryDepth := 0
	var names []string
	var listens []vhost

	flush := func() {
		if len(listens) == 0 {
			listens = []vhost{{Port: 80}}
		}
		if len(names) == 0 {
			names = []string{"_"}
		}
		for _, n := range names {
			for _, l := range listens {
				hosts = append(hosts, vhost{Name: n, Port: l.Port, SSL: l.SSL})
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
			entryDepth = depth
		}
		if inServer {
			if strings.HasPrefix(trimmed, "server_name ") {
				for _, n := range strings.Fields(strings.TrimSuffix(strings.TrimPrefix(trimmed, "server_name "), ";")) {
					names = append(names, strings.TrimSuffix(n, ";"))
				}
			}
			if strings.HasPrefix(trimmed, "listen ") {
				fields := strings.Fields(strings.TrimSuffix(strings.TrimPrefix(trimmed, "listen "), ";"))
				if len(fields) > 0 {
					addr := fields[0]
					if i := strings.LastIndexByte(addr, ':'); i >= 0 {
						addr = addr[i+1:]
					}
					if port, err := strconv.Atoi(addr); err == nil && port > 0 {
						ssl := false
						for _, f := range fields[1:] {
							if f == "ssl" {
								ssl = true
							}
						}
						listens = append(listens, vhost{Port: port, SSL: ssl})
					}
				}
			}
		}
		depth += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
		if inServer && depth <= entryDepth {
			flush()
			inServer = false
		}
	}
	return dedupeVhosts(hosts)
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
			hosts = append(hosts, vhost{Name: m[2], Port: port, SSL: port == 443})
			continue
		}
		if m := apacheNameRe.FindStringSubmatch(line); m != nil {
			port, _ := strconv.Atoi(m[1])
			hosts = append(hosts, vhost{Name: m[2], Port: port, SSL: port == 443})
			continue
		}
		if m := apacheDefaultRe.FindStringSubmatch(line); m != nil && curPort > 0 {
			hosts = append(hosts, vhost{Name: m[1], Port: curPort, SSL: curPort == 443})
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
