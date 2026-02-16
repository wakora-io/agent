package defs

import (
	"bufio"
	"net"
	"strings"
	"time"

	"wakora.io/agent/internal/protocol"
)

func runHAProxy(o *Outcome, service string, p protocol.Probe, timeout time.Duration) {
	sock := p.Path
	if sock == "" {
		sock = "/var/run/haproxy.sock"
	}
	o.Check.Target = "unix://" + sock

	info, err := haproxyCommand(sock, "show info", timeout)
	if err != nil {
		o.Check.Status = "fail"
		o.Check.Error = err.Error()
		return
	}
	stat, err := haproxyCommand(sock, "show stat", timeout)
	if err != nil {
		o.Check.Status = "fail"
		o.Check.Error = err.Error()
		return
	}
	o.Check.Status = "ok"

	prefix := "svc." + service + "."
	kv := parseHAProxyInfo(info)
	if v := kv["Version"]; v != "" {
		o.Facts = map[string]string{"version": v}
	}
	for name, key := range map[string]string{
		"current_connections": "CurrConns",
		"conn_rate":           "ConnRate",
		"uptime":              "Uptime_sec",
	} {
		if f, ok := parseNum(kv[key]); ok {
			o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: prefix + name, Value: f})
		}
	}
	o.Metrics = append(o.Metrics, haproxyStatMetrics(prefix, stat)...)
}

func haproxyCommand(sock, cmd string, timeout time.Duration) (string, error) {
	conn, err := net.DialTimeout("unix", sock, timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(cmd + "\n")); err != nil {
		return "", err
	}
	var b strings.Builder
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		b.WriteString(sc.Text())
		b.WriteByte('\n')
	}
	return b.String(), nil
}

func parseHAProxyInfo(raw string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}

func haproxyStatMetrics(prefix, raw string) []protocol.MetricPoint {
	lines := strings.Split(raw, "\n")
	if len(lines) == 0 {
		return nil
	}
	header := strings.TrimPrefix(strings.TrimSpace(lines[0]), "# ")
	col := map[string]int{}
	for i, name := range strings.Split(header, ",") {
		col[name] = i
	}
	get := func(fields []string, name string) (string, bool) {
		i, ok := col[name]
		if !ok || i >= len(fields) {
			return "", false
		}
		return fields[i], true
	}
	num := func(fields []string, name string) (float64, bool) {
		s, ok := get(fields, name)
		if !ok || s == "" {
			return 0, false
		}
		return parseNum(s)
	}

	var pts []protocol.MetricPoint
	var backendsUp, backendsTotal, serversUp, serversTotal float64
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Split(line, ",")
		pxname, _ := get(fields, "pxname")
		svname, _ := get(fields, "svname")
		if pxname == "" || svname == "" {
			continue
		}
		status, _ := get(fields, "status")
		up := 0.0
		if strings.HasPrefix(status, "UP") || status == "OPEN" || status == "no check" {
			up = 1
		}

		var tags map[string]string
		emit := func(name string, value float64) {
			pts = append(pts, protocol.MetricPoint{Name: prefix + name, Value: value, Tags: tags})
		}
		switch svname {
		case "FRONTEND":
			tags = map[string]string{"proxy": pxname, "kind": "frontend"}
			if v, ok := num(fields, "scur"); ok {
				emit("proxy.sessions", v)
			}
			if v, ok := num(fields, "stot"); ok {
				emit("proxy.sessions_total", v)
			}
			if v, ok := num(fields, "hrsp_5xx"); ok {
				emit("proxy.hrsp_5xx_total", v)
			}
		case "BACKEND":
			backendsTotal++
			backendsUp += up
			tags = map[string]string{"proxy": pxname, "kind": "backend"}
			emit("proxy.up", up)
			if v, ok := num(fields, "scur"); ok {
				emit("proxy.sessions", v)
			}
			if v, ok := num(fields, "stot"); ok {
				emit("proxy.sessions_total", v)
			}
			if v, ok := num(fields, "hrsp_5xx"); ok {
				emit("proxy.hrsp_5xx_total", v)
			}
			if v, ok := num(fields, "econ"); ok {
				emit("proxy.conn_errors_total", v)
			}
			if v, ok := num(fields, "act"); ok {
				emit("proxy.active_servers", v)
			}
		default:
			serversTotal++
			serversUp += up
			tags = map[string]string{"proxy": pxname, "server": svname}
			emit("server.up", up)
			if v, ok := num(fields, "scur"); ok {
				emit("server.sessions", v)
			}
			if v, ok := num(fields, "hrsp_5xx"); ok {
				emit("server.hrsp_5xx_total", v)
			}
		}
	}
	pts = append(pts,
		protocol.MetricPoint{Name: prefix + "backends_up", Value: backendsUp},
		protocol.MetricPoint{Name: prefix + "backends_total", Value: backendsTotal},
		protocol.MetricPoint{Name: prefix + "servers_up", Value: serversUp},
		protocol.MetricPoint{Name: prefix + "servers_total", Value: serversTotal},
	)
	return pts
}
