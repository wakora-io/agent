package defs

import (
	"context"
	"os/exec"
	"sort"
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
	names := make([]string, 0, len(states))
	for name := range states {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		state := states[name]
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

	poolOut, _ := exec.CommandContext(ctx, path, "-r", "pool-list", "--details").Output()
	for pool, pv := range parseVirshPools(string(poolOut)) {
		tags := map[string]string{"storage": pool}
		if v, ok := pv["capacity"]; ok && v > 0 {
			o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: prefix + "storage.capacity_bytes", Value: v, Tags: tags})
			if a, ok := pv["allocation"]; ok {
				o.Metrics = append(o.Metrics,
					protocol.MetricPoint{Name: prefix + "storage.used_bytes", Value: a, Tags: copyTags(tags)},
					protocol.MetricPoint{Name: prefix + "storage.used_pct", Value: a / v * 100, Tags: copyTags(tags)},
				)
			}
		}
	}
}

func parseVirshPools(out string) map[string]map[string]float64 {
	res := map[string]map[string]float64{}
	unit := func(v, u string) (float64, bool) {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return 0, false
		}
		switch strings.ToUpper(strings.TrimSpace(u)) {
		case "KIB":
			f *= 1 << 10
		case "MIB":
			f *= 1 << 20
		case "GIB":
			f *= 1 << 30
		case "TIB":
			f *= 1 << 40
		case "PIB":
			f *= 1 << 50
		case "B", "BYTES":
		default:
			return 0, false
		}
		return f, true
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 10 || f[0] == "Name" || strings.HasPrefix(f[0], "---") {
			continue
		}
		if strings.ToLower(f[1]) != "running" {
			continue
		}
		vals := map[string]float64{}
		if v, ok := unit(f[4], f[5]); ok {
			vals["capacity"] = v
		}
		if v, ok := unit(f[6], f[7]); ok {
			vals["allocation"] = v
		}
		if len(vals) > 0 {
			res[f[0]] = vals
		}
	}
	return res
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
