//go:build windows

package defs

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"wakora.io/agent/internal/protocol"
)

func appcmdPath() string {
	root := os.Getenv("windir")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "system32", "inetsrv", "appcmd.exe")
}

func runIIS(o *Outcome, service string, p protocol.Probe, timeout time.Duration) {
	appcmd := appcmdPath()
	if _, err := os.Stat(appcmd); err != nil {
		o.Check.Status = "fail"
		o.Check.Error = "appcmd not found: " + appcmd
		return
	}
	o.Check.Target = appcmd
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	sitesOut, err := exec.CommandContext(ctx, appcmd, "list", "sites").Output()
	if err != nil {
		o.Check.Status = "fail"
		o.Check.Error = strings.TrimSpace(err.Error())
		return
	}
	poolsOut, _ := exec.CommandContext(ctx, appcmd, "list", "apppools").Output()
	wpsOut, _ := exec.CommandContext(ctx, appcmd, "list", "wps").Output()

	prefix := "svc." + service + "."
	var sites, sitesStarted float64
	for _, st := range parseIISSites(string(sitesOut)) {
		sites++
		up := 0.0
		if strings.EqualFold(st.state, "Started") {
			up = 1
			sitesStarted++
		}
		tags := map[string]string{"site": st.name}
		o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: prefix + "site.started", Value: up, Tags: tags})
		if len(st.hosts) > 0 {
			for _, h := range st.hosts {
				payload, _ := json.Marshal(map[string]string{"state": st.state, "site": st.name})
				o.InvFacts = append(o.InvFacts, protocol.Fact{Kind: "vhost", Key: h, Payload: string(payload)})
			}
		} else {
			payload, _ := json.Marshal(map[string]string{"state": st.state})
			o.InvFacts = append(o.InvFacts, protocol.Fact{Kind: "vhost", Key: st.name, Payload: string(payload)})
		}
	}
	var pools, poolsStarted float64
	for name, state := range parseAppcmd(string(poolsOut), "APPPOOL") {
		pools++
		up := 0.0
		if strings.EqualFold(state, "Started") {
			up = 1
			poolsStarted++
		}
		o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: prefix + "pool.started", Value: up, Tags: map[string]string{"pool": name}})
	}
	workers := float64(strings.Count(string(wpsOut), "WP \""))

	if dirs := iisLogDirs(ctx, appcmd, string(sitesOut)); len(dirs) > 0 {
		if o.Facts == nil {
			o.Facts = map[string]string{}
		}
		o.Facts["accessLog"] = strings.Join(dirs, ",")
	}

	o.Check.Status = "ok"
	o.Metrics = append(o.Metrics,
		protocol.MetricPoint{Name: prefix + "sites", Value: sites},
		protocol.MetricPoint{Name: prefix + "sites_started", Value: sitesStarted},
		protocol.MetricPoint{Name: prefix + "pools", Value: pools},
		protocol.MetricPoint{Name: prefix + "pools_started", Value: poolsStarted},
		protocol.MetricPoint{Name: prefix + "worker_processes", Value: workers},
	)
}

var iisSiteIDRe = regexp.MustCompile(`SITE "([^"]+)" \(id:(\d+)`)

func iisLogDirs(ctx context.Context, appcmd, sitesOut string) []string {
	seen := map[string]bool{}
	var out []string
	matches := iisSiteIDRe.FindAllStringSubmatch(sitesOut, -1)
	if len(matches) > 20 {
		matches = matches[:20]
	}
	for _, m := range matches {
		dirOut, err := exec.CommandContext(ctx, appcmd, "list", "site", m[1], "/text:logFile.directory").Output()
		if err != nil {
			continue
		}
		dir := strings.TrimSpace(string(dirOut))
		if dir == "" {
			continue
		}
		dir = os.ExpandEnv(strings.ReplaceAll(strings.ReplaceAll(dir, "%SystemDrive%", "${SystemDrive}"), "%windir%", "${windir}"))
		full := filepath.Join(dir, "W3SVC"+m[2])
		if _, err := os.Stat(full); err != nil || seen[full] {
			continue
		}
		seen[full] = true
		out = append(out, full)
	}
	return out
}
