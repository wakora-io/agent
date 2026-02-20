package defs

import (
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"wakora.io/agent/internal/protocol"
)

var (
	kaVipBlockRe = regexp.MustCompile(`(?s)virtual_ipaddress\s*\{([^}]*)\}`)
	kaPrioRe     = regexp.MustCompile(`(?m)^\s*priority\s+(\d+)`)
	kaStateRe    = regexp.MustCompile(`(?m)^\s*state\s+(\w+)`)
	kaVridRe     = regexp.MustCompile(`(?m)^\s*virtual_router_id\s+(\d+)`)
	kaIPRe       = regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)
)

func runKeepalived(o *Outcome, service string, p protocol.Probe) {
	path := p.Path
	if path == "" {
		path = "/etc/keepalived/keepalived.conf"
	}
	o.Check.Target = path
	data, err := os.ReadFile(path)
	if err != nil {
		o.Check.Status = "fail"
		o.Check.Error = err.Error()
		return
	}
	o.Check.Status = "ok"
	conf := string(data)

	var vips []string
	if m := kaVipBlockRe.FindStringSubmatch(conf); len(m) > 1 {
		vips = kaIPRe.FindAllString(m[1], -1)
	}
	local := localAddrs()
	held := 0
	for _, vip := range vips {
		if local[vip] {
			held++
		}
	}
	active := 0.0
	if len(vips) > 0 && held == len(vips) {
		active = 1
	}
	o.Metrics = append(o.Metrics,
		protocol.MetricPoint{Name: "svc." + service + ".active", Value: active},
		protocol.MetricPoint{Name: "svc." + service + ".vips_held", Value: float64(held)},
	)
	if m := kaPrioRe.FindStringSubmatch(conf); len(m) > 1 {
		if v, e := strconv.ParseFloat(m[1], 64); e == nil {
			o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: "svc." + service + ".priority", Value: v})
		}
	}
	o.Facts = map[string]string{}
	if len(vips) > 0 {
		o.Facts["vip"] = strings.Join(vips, ",")
	}
	if m := kaStateRe.FindStringSubmatch(conf); len(m) > 1 {
		o.Facts["configuredState"] = m[1]
	}
	if m := kaVridRe.FindStringSubmatch(conf); len(m) > 1 {
		o.Facts["vrid"] = m[1]
	}
}

func localAddrs() map[string]bool {
	out := map[string]bool{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			out[ipn.IP.String()] = true
		}
	}
	return out
}
