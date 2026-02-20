//go:build windows

package defs

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
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
	for name, state := range parseAppcmd(string(sitesOut), "SITE") {
		sites++
		up := 0.0
		if strings.EqualFold(state, "Started") {
			up = 1
			sitesStarted++
		}
		tags := map[string]string{"site": name}
		o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: prefix + "site.started", Value: up, Tags: tags})
		payload, _ := json.Marshal(map[string]string{"state": state})
		o.InvFacts = append(o.InvFacts, protocol.Fact{Kind: "site", Key: name, Payload: string(payload)})
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

	o.Check.Status = "ok"
	o.Metrics = append(o.Metrics,
		protocol.MetricPoint{Name: prefix + "sites", Value: sites},
		protocol.MetricPoint{Name: prefix + "sites_started", Value: sitesStarted},
		protocol.MetricPoint{Name: prefix + "pools", Value: pools},
		protocol.MetricPoint{Name: prefix + "pools_started", Value: poolsStarted},
		protocol.MetricPoint{Name: prefix + "worker_processes", Value: workers},
	)
}
