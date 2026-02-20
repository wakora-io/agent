package defs

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"wakora.io/agent/internal/protocol"
)

func runVirsh(o *Outcome, service string, p protocol.Probe, timeout time.Duration) {
	o.Check.Target = "virsh list/domstats"
	path, err := exec.LookPath("virsh")
	if err != nil {
		o.Check.Status = "fail"
		o.Check.Error = err.Error()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	listOut, err := exec.CommandContext(ctx, path, "-r", "list", "--all").Output()
	if err != nil {
		o.Check.Status = "fail"
		o.Check.Error = strings.TrimSpace(err.Error())
		return
	}
	o.Check.Status = "ok"

	states := parseVirshList(string(listOut))
	statsOut, _ := exec.CommandContext(ctx, path, "-r", "domstats").Output()
	stats := parseVirshDomstats(string(statsOut))

	prefix := "svc." + service + "."
	var total, running float64
	for name, state := range states {
		total++
		up := 0.0
		if state == "running" {
			up = 1
			running++
		}
		tags := map[string]string{"domain": name}
		o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: prefix + "guest.running", Value: up, Tags: tags})
		if s := stats[name]; s != nil {
			if v, ok := s["vcpu.current"]; ok {
				o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: prefix + "guest.vcpus", Value: v, Tags: copyTags(tags)})
			}
			if v, ok := s["balloon.current"]; ok {
				o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: prefix + "guest.mem_bytes", Value: v * 1024, Tags: copyTags(tags)})
			}
			if v, ok := s["cpu.time"]; ok {
				o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: prefix + "guest.cpu_time_ns", Value: v, Tags: copyTags(tags)})
			}
		}
		if o.Facts == nil {
			o.Facts = map[string]string{}
		}
		o.InvFacts = append(o.InvFacts, protocol.Fact{Kind: "guest", Key: name, Payload: `{"state":"` + state + `","hv":"kvm"}`})
	}
	o.Metrics = append(o.Metrics,
		protocol.MetricPoint{Name: prefix + "domains", Value: total},
		protocol.MetricPoint{Name: prefix + "running", Value: running},
	)
}

func parseVirshList(out string) map[string]string {
	res := map[string]string{}
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] == "Id" || strings.HasPrefix(f[0], "---") {
			continue
		}
		name := f[1]
		state := strings.ToLower(strings.Join(f[2:], " "))
		res[name] = state
	}
	return res
}

func parseVirshDomstats(out string) map[string]map[string]float64 {
	res := map[string]map[string]float64{}
	var cur string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Domain:") {
			name := strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "Domain:")), "'")
			cur = name
			res[cur] = map[string]float64{}
			continue
		}
		if cur == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
			res[cur][strings.TrimSpace(k)] = f
		}
	}
	return res
}
