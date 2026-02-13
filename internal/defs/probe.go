package defs

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"wakora.io/agent/internal/protocol"
	"wakora.io/agent/internal/secret"
)

type Outcome struct {
	Check    protocol.CheckResult
	Extra    []protocol.CheckResult
	Metrics  []protocol.MetricPoint
	Facts    map[string]string
	InvFacts []protocol.Fact
}

var execAllowlist = map[string]bool{
	"nginx": true, "apache2ctl": true, "httpd": true, "php-fpm": true,
	"mariadbd": true, "mysqld": true, "mysqladmin": true, "mariadb-admin": true,
	"redis-cli": true, "psql": true, "postconf": true,
}

func RunProbe(service string, p protocol.Probe) Outcome {
	return RunProbeWithSecrets(service, p, func(string) (secret.Cred, bool) { return secret.Cred{}, false })
}

func RunProbeWithSecrets(service string, p protocol.Probe, resolve CredResolver) Outcome {
	timeout := time.Duration(p.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	o := Outcome{Check: protocol.CheckResult{
		CheckID:   service + "/" + p.Name,
		Kind:      p.Type,
		Timestamp: time.Now().Unix(),
	}}
	start := time.Now()
	switch p.Type {
	case "http":
		o.Check.Target = p.URL
		client := &http.Client{Timeout: timeout}
		resp, err := client.Get(p.URL)
		if err != nil {
			o.Check.Status = "fail"
			o.Check.Error = err.Error()
			break
		}
		resp.Body.Close()
		want := p.ExpectStatus
		if want == 0 {
			want = 200
		}
		if resp.StatusCode == want {
			o.Check.Status = "ok"
		} else {
			o.Check.Status = "fail"
			o.Check.Error = fmt.Sprintf("status %d, want %d", resp.StatusCode, want)
		}
	case "tcp":
		o.Check.Target = p.Address
		conn, err := net.DialTimeout("tcp", p.Address, timeout)
		if err != nil {
			o.Check.Status = "fail"
			o.Check.Error = err.Error()
		} else {
			conn.Close()
			o.Check.Status = "ok"
		}
	case "exec":
		runExec(&o, p, timeout)
	case "vhosts":
		runVhosts(&o, service, p, timeout)
	case "sql":
		runSQL(&o, service, p, timeout, resolve)
	case "redis":
		runRedis(&o, service, p, timeout, resolve)
	default:
		o.Check.Status = "fail"
		o.Check.Error = "unknown probe type " + p.Type
	}
	o.Check.LatencyMs = float64(time.Since(start).Microseconds()) / 1000
	if o.Check.Status == "ok" && (p.Type == "http" || p.Type == "tcp") {
		o.Metrics = append(o.Metrics, protocol.MetricPoint{
			Name:  "svc." + service + "." + p.Name + ".latency_ms",
			Value: o.Check.LatencyMs,
		})
	}
	return o
}

func runExec(o *Outcome, p protocol.Probe, timeout time.Duration) {
	o.Check.Target = strings.TrimSpace(p.Command + " " + strings.Join(p.Args, " "))
	if p.Command == "" || strings.ContainsAny(p.Command, "/\\") || !execAllowlist[p.Command] {
		o.Check.Status = "fail"
		o.Check.Error = "command not in allow-list"
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
	out, err := exec.CommandContext(ctx, path, p.Args...).CombinedOutput()
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
	for _, r := range p.Metrics {
		v, ok := extract(out, r.Regex)
		if !ok {
			continue
		}
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: r.Name, Value: f})
		}
	}
	for _, r := range p.Facts {
		var v string
		var ok bool
		if r.All {
			v, ok = extractAll(out, r.Regex)
		} else {
			v, ok = extract(out, r.Regex)
		}
		if !ok {
			continue
		}
		if o.Facts == nil {
			o.Facts = map[string]string{}
		}
		o.Facts[r.Name] = v
	}
}

func extractAll(out []byte, pattern string) (string, bool) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", false
	}
	seen := map[string]bool{}
	var vals []string
	for _, m := range re.FindAllSubmatch(out, -1) {
		if len(m) < 2 {
			continue
		}
		v := strings.TrimSpace(string(m[1]))
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		vals = append(vals, v)
	}
	if len(vals) == 0 {
		return "", false
	}
	return strings.Join(vals, ","), true
}

func extract(out []byte, pattern string) (string, bool) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", false
	}
	m := re.FindSubmatch(out)
	if len(m) < 2 {
		return "", false
	}
	return strings.TrimSpace(string(m[1])), true
}
