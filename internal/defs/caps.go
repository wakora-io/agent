package defs

import (
	"strings"

	"wakora.io/agent/internal/protocol"
)

const (
	capCreds    = "creds"
	capExec     = "exec"
	capDB       = "db"
	capFiles    = "files"
	capNetwork  = "network"
	capDevice   = "device"
	capInsecure = "insecure"
)

var probeCap = map[string]string{
	"exec":        capExec,
	"sql":         capDB,
	"redis":       capDB,
	"file":        capFiles,
	"logs":        capFiles,
	"logtail":     capFiles,
	"journal":     capFiles,
	"snmp":        capNetwork,
	"snmpscan":    capNetwork,
	"traps":       capNetwork,
	"syslog":      capNetwork,
	"netflow":     capNetwork,
	"ext":         capNetwork,
	"domain":      capNetwork,
	"configfetch": capDevice,
}

var probeFree = map[string]bool{
	"http":     true,
	"tcp":      true,
	"procfact": true,
	"vhosts":   true,
}

func grantedCaps(d *protocol.Definition) map[string]bool {
	g := map[string]bool{}
	if len(d.Capabilities) == 0 && strings.HasPrefix(d.Service, "device_") {
		g[capCreds] = true
		g[capNetwork] = true
		g[capDevice] = true
		return g
	}
	for _, c := range d.Capabilities {
		if c = strings.ToLower(strings.TrimSpace(c)); c != "" {
			g[c] = true
		}
	}
	return g
}

func tenantMetricPrefixes(service string) []string {
	out := []string{"svc." + service + "."}
	if strings.HasPrefix(service, "device_") {
		out = append(out, "dev.")
	}
	return out
}

func metricNameOK(name string, prefixes []string) bool {
	n := strings.TrimSpace(name)
	for _, p := range prefixes {
		if strings.HasPrefix(n, p) && len(n) > len(p) {
			return true
		}
	}
	return false
}

func SanitizeTenant(d *protocol.Definition) {
	granted := grantedCaps(d)
	prefixes := tenantMetricPrefixes(d.Service)
	isDevice := strings.HasPrefix(d.Service, "device_")
	for i := range d.Probes {
		p := &d.Probes[i]
		t := strings.ToLower(strings.TrimSpace(p.Type))
		if t == "configfetch" && !isDevice {
			p.Denied = "config backup runs only on approved network devices"
			continue
		}
		if need, known := probeCap[t]; known {
			if !granted[need] {
				p.Denied = "this template runs without the " + need + " capability"
				continue
			}
		} else if !probeFree[t] {
			p.Denied = "probe type " + t + " is not available to workspace templates"
			continue
		}
		if !granted[capCreds] {
			p.Secret = ""
			p.SecretOpt = ""
		}
		if !granted[capInsecure] {
			p.Insecure = false
		}
		sanitizeProbeNames(p, prefixes)
	}
	d.Derived = keepNamed(d.Derived, prefixes, func(r protocol.DerivedRule) string { return r.Name })
}

func sanitizeProbeNames(p *protocol.Probe, prefixes []string) {
	p.Metrics = keepNamed(p.Metrics, prefixes, func(r protocol.ParseRule) string { return r.Name })
	p.Prom = keepNamed(p.Prom, prefixes, func(r protocol.PromRule) string { return r.Name })
	p.KVMetrics = keepNamed(p.KVMetrics, prefixes, func(r protocol.KVMetric) string { return r.Name })
	p.KVRatios = keepNamed(p.KVRatios, prefixes, func(r protocol.KVRatio) string { return r.Name })
	p.Get = keepNamed(p.Get, prefixes, func(r protocol.OID) string { return r.Name })
	p.Walk = keepNamed(p.Walk, prefixes, func(r protocol.OID) string { return r.Name })
	p.Counters = keepCounters(p.Counters, prefixes)
	p.Rates = keepRates(p.Rates, prefixes)
	if p.LinkState != nil && !metricNameOK(p.LinkState.Out, prefixes) {
		p.LinkState = nil
	}
}

func keepNamed[T any](in []T, prefixes []string, name func(T) string) []T {
	if len(in) == 0 {
		return in
	}
	out := make([]T, 0, len(in))
	for _, v := range in {
		if metricNameOK(name(v), prefixes) {
			out = append(out, v)
		}
	}
	return out
}

func keepCounters(in []protocol.Counter, prefixes []string) []protocol.Counter {
	if len(in) == 0 {
		return in
	}
	out := make([]protocol.Counter, 0, len(in))
	for _, c := range in {
		if !metricNameOK(c.Name, prefixes) {
			continue
		}
		c.Event = ""
		out = append(out, c)
	}
	return out
}

func keepRates(in []protocol.RateRule, prefixes []string) []protocol.RateRule {
	if len(in) == 0 {
		return in
	}
	out := make([]protocol.RateRule, 0, len(in))
	for _, r := range in {
		if strings.TrimSpace(r.Out) == "" || metricNameOK(r.Out, prefixes) {
			out = append(out, r)
		}
	}
	return out
}
