package defs

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"wakora.io/agent/internal/protocol"
	"wakora.io/agent/internal/secret"
)

func recoverProbe(o *Outcome, r any) {
	o.Check.Status = "fail"
	o.Check.Error = fmt.Sprintf("probe panicked: %v", r)
	o.Metrics = nil
	o.Extra = nil
	o.InvFacts = nil
	o.Events = nil
	o.ProfileStacks = nil
	log.Printf("probe %s panicked: %v\n%s", o.Check.CheckID, r, debug.Stack())
}

type Outcome struct {
	Check         protocol.CheckResult
	Extra         []protocol.CheckResult
	Metrics       []protocol.MetricPoint
	Facts         map[string]string
	InvFacts      []protocol.Fact
	Events        []protocol.AgentEvent
	ProfileStacks []protocol.FoldedStack
	ProfileMeta   protocol.ProfileBatch
}

var execAllowlist = map[string]bool{
	"nginx": true, "apache2ctl": true, "httpd": true, "php-fpm": true,
	"mariadbd": true, "mysqld": true, "mysqladmin": true, "mariadb-admin": true,
	"redis-cli": true, "psql": true, "postconf": true, "postqueue": true, "mailq": true,
	"dovecot": true, "doveadm": true, "doveconf": true, "named": true, "rndc": true, "named-checkconf": true,
	"apt-get": true, "dnf": true, "yum": true, "rpm": true, "zypper": true, "apk": true,
	"vsftpd": true, "pure-ftpd": true, "pure-ftpd-mysql": true, "pure-ftpwho": true,
	"pveversion": true, "qm": true, "pct": true, "pvesm": true,
	"mongosh": true, "mongo": true, "systemctl": true,
	"varnishstat": true, "unbound-control": true, "exim": true, "exim4": true,
	"pmgsh": true, "pmgversion": true,
	"restic": true, "borg": true,
	"sshd": true,
}

func RunProbe(service string, p protocol.Probe) Outcome {
	return RunProbeWithSecrets(service, p, func(string) (secret.Cred, bool) { return secret.Cred{}, false })
}

func RunProbeWithSecrets(service string, p protocol.Probe, resolve CredResolver) (o Outcome) {
	timeout := time.Duration(p.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	o = Outcome{Check: protocol.CheckResult{
		CheckID:   service + "/" + p.Name,
		Kind:      p.Type,
		Timestamp: time.Now().Unix(),
	}}
	defer func() {
		if r := recover(); r != nil {
			recoverProbe(&o, r)
		}
	}()
	start := time.Now()
	switch p.Type {
	case "http":
		runHTTP(&o, p, timeout, resolve)
	case "tcp":
		o.Check.Target = p.Address
		if p.Address == "" {
			o.Check.Status = "fail"
			if p.PortProcess != "" {
				o.Check.Error = "no listening tcp port owned by process " + p.PortProcess + " - the socket may be held by systemd (socket activation); the configured port is used once discovered"
			} else {
				o.Check.Error = "no address to dial"
			}
			break
		}
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
	case "snmp":
		runSNMP(&o, service, p, timeout, resolve)
	case "docker":
		runDocker(&o, service, p, timeout)
	case "file":
		runFile(&o, service, p)
	case "pve":
		runPVE(&o, service, p, timeout)
	case "haproxy":
		runHAProxy(&o, service, p, timeout)
	case "domain":
		runDomain(&o, service, p, timeout)
	case "ext":
		runExt(&o, service, p, timeout)
	case "snmpscan":
		runSNMPScan(&o, service, p, timeout, resolve)
	case "keepalived":
		runKeepalived(&o, service, p)
	case "virsh":
		runVirsh(&o, service, p, timeout)
	case "k8s":
		runK8s(&o, service, p, timeout)
	case "wineventlog":
		runEventLog(&o, service, p)
	case "iis":
		runIIS(&o, service, p, timeout)
	case "hyperv":
		runHyperV(&o, service, p)
	case "cis":
		runCIS(&o, service)
	case "drbd":
		runDRBD(&o, service, timeout)
	case "fpmpool":
		runFPMPool(&o, service, p)
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

func runHTTP(o *Outcome, p protocol.Probe, timeout time.Duration, resolve CredResolver) {
	urls := p.URLs
	if len(urls) == 0 {
		urls = []string{p.URL}
	}
	o.Check.Target = urls[0]
	optionalUnset := false
	var cred secret.Cred
	hasCred := false
	if p.Secret != "" {
		c, ok := resolve(p.Secret)
		if !ok {
			o.Check.Status = "fail"
			o.Check.Error = "secret " + p.Secret + " not set on host (wakora secret set)"
			return
		}
		cred = c
		hasCred = true
	} else if p.SecretOpt != "" {
		if c, ok := resolve(p.SecretOpt); ok {
			cred = c
			hasCred = true
		} else {
			optionalUnset = true
		}
	}
	client := &http.Client{Timeout: timeout}
	if p.Insecure {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	var resp *http.Response
	var lastErr error
	for _, u := range urls {
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", probeUserAgent)
		if hasCred {
			if p.Bearer {
				req.Header.Set("Authorization", "Bearer "+cred.Pass)
			} else if p.AuthHeader != "" {
				req.Header.Set(p.AuthHeader, cred.Pass)
			} else {
				req.SetBasicAuth(cred.User, cred.Pass)
			}
		}
		r, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		resp = r
		o.Check.Target = u
		break
	}
	if resp == nil {
		o.Check.Status = "fail"
		o.Check.Error = lastErr.Error()
		return
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	resp.Body.Close()
	want := p.ExpectStatus
	if want == 0 {
		want = 200
	}
	if resp.StatusCode != want {
		o.Check.Status = "fail"
		o.Check.Error = fmt.Sprintf("status %d, want %d", resp.StatusCode, want)
		if optionalUnset && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
			o.Check.Error += " - set a monitoring credential: wakora secret set " + p.SecretOpt
		}
		return
	}
	o.Check.Status = "ok"
	applyMetricRules(o, p.Metrics, body)
	applyProm(o, p.Prom, body)
	applyFactRules(o, p.Facts, body)
}

func runFile(o *Outcome, service string, p protocol.Probe) {
	o.Check.Target = p.Path
	if p.Path == "" {
		o.Check.Status = "fail"
		o.Check.Error = "file path not set"
		return
	}
	fi, err := os.Stat(p.Path)
	if err != nil {
		if !os.IsNotExist(err) {
			o.Check.Status = "fail"
			o.Check.Error = err.Error()
			return
		}
		o.Check.Status = "ok"
		o.Metrics = append(o.Metrics, protocol.MetricPoint{
			Name: "svc." + service + "." + p.Name + ".exists", Value: 0,
		})
		return
	}
	o.Check.Status = "ok"
	o.Metrics = append(o.Metrics, protocol.MetricPoint{
		Name: "svc." + service + "." + p.Name + ".exists", Value: 1,
	})
	if p.Age {
		mtime := fi.ModTime()
		if fi.IsDir() {
			if newest, ok := newestFileIn(p.Path); ok {
				mtime = newest
			}
		}
		o.Metrics = append(o.Metrics, protocol.MetricPoint{
			Name: "svc." + service + "." + p.Name + ".age_sec", Value: time.Since(mtime).Seconds(),
		})
	}
	if fi.IsDir() || (len(p.Metrics) == 0 && len(p.Facts) == 0 && !p.Hash) {
		return
	}
	data, err := os.ReadFile(p.Path)
	if err != nil {
		o.Check.Status = "fail"
		o.Check.Error = err.Error()
		return
	}
	if len(data) > 1<<20 {
		data = data[:1<<20]
	}
	applyMetricRules(o, p.Metrics, data)
	applyFactRules(o, p.Facts, data)
	if p.Hash {
		sum := sha256.Sum256(data)
		if o.Facts == nil {
			o.Facts = map[string]string{}
		}
		o.Facts[p.Name+"Sha256"] = hex.EncodeToString(sum[:])
	}
}

func newestFileIn(dir string) (time.Time, bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return time.Time{}, false
	}
	var newest time.Time
	found := false
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(newest) {
			newest = info.ModTime()
			found = true
		}
	}
	return newest, found
}

func applyMetricRules(o *Outcome, rules []protocol.ParseRule, body []byte) {
	for _, r := range rules {
		if r.Count {
			o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: r.Name, Value: float64(extractCount(body, r.Regex))})
			continue
		}
		v, ok := extract(body, r.Regex)
		if !ok {
			continue
		}
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: r.Name, Value: f})
		}
	}
}

func applyFactRules(o *Outcome, rules []protocol.ParseRule, body []byte) {
	for _, r := range rules {
		var v string
		var ok bool
		if r.All {
			v, ok = extractAll(body, r.Regex)
		} else {
			v, ok = extract(body, r.Regex)
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

func extractCount(out []byte, pattern string) int {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return 0
	}
	return len(re.FindAllIndex(out, -1))
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
	if err != nil && !exitCodeAllowed(p, err) {
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
	applyMetricRules(o, p.Metrics, out)
	applyFactRules(o, p.Facts, out)
}

func exitCodeAllowed(p protocol.Probe, err error) bool {
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return false
	}
	for _, c := range p.OKCodes {
		if ee.ExitCode() == c {
			return true
		}
	}
	return false
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
