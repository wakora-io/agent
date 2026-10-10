package defs

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type ListenPort struct {
	Pid     int
	Process string
}

var listenPorts atomic.Value

func SetListenPorts(m map[int]ListenPort) {
	listenPorts.Store(m)
}

func currentListenPorts() map[int]ListenPort {
	m, _ := listenPorts.Load().(map[int]ListenPort)
	return m
}

var vhostUpstreamsCache sync.Map

var nginxPassDirectives = map[string]string{
	"fastcgi_pass": "", "proxy_pass": "http", "uwsgi_pass": "", "scgi_pass": "", "grpc_pass": "grpc",
}

func scanNginxUpstreams(out []byte) map[string][]string {
	ups := map[string][]string{}
	name := ""
	depth := 0
	entry := 0
	for _, raw := range strings.Split(string(out), "\n") {
		line := raw
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		stmts, rest := splitNginxStatements(trimmed)
		if rest != "" {
			stmts = append(stmts, rest)
		}
		for _, st := range stmts {
			f := strings.Fields(st)
			if name == "" && len(f) >= 2 && f[0] == "upstream" {
				name = f[1]
				entry = depth
				if _, ok := ups[name]; !ok {
					ups[name] = nil
				}
				continue
			}
			if name != "" && len(f) >= 2 && f[0] == "server" {
				ups[name] = append(ups[name], f[1])
			}
		}
		depth += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
		if name != "" && depth <= entry && strings.Contains(trimmed, "}") {
			name = ""
		}
	}
	return ups
}

type backendTarget struct {
	unix string
	host string
	port int
}

func (t backendTarget) String() string {
	if t.unix != "" {
		return "unix:" + t.unix
	}
	return net.JoinHostPort(t.host, strconv.Itoa(t.port))
}

func backendTargets(directive, pass string, upstreams map[string][]string) ([]backendTarget, bool) {
	p := strings.TrimSpace(pass)
	if p == "" || strings.ContainsRune(p, '$') {
		return nil, false
	}
	scheme := nginxPassDirectives[directive]
	if i := strings.Index(p, "://"); i >= 0 {
		scheme = strings.ToLower(p[:i])
		p = p[i+3:]
	}
	if i := strings.IndexByte(p, '/'); i > 0 && !strings.HasPrefix(p, "unix:") {
		p = p[:i]
	}
	if servers, ok := upstreams[p]; ok {
		if len(servers) == 0 {
			return nil, false
		}
		var out []backendTarget
		for _, s := range servers {
			t, ok := backendAddr(s, scheme)
			if !ok {
				return nil, false
			}
			out = append(out, t)
		}
		return out, true
	}
	t, ok := backendAddr(p, scheme)
	if !ok {
		return nil, false
	}
	return []backendTarget{t}, true
}

func backendAddr(addr, scheme string) (backendTarget, bool) {
	if strings.HasPrefix(addr, "unix:") {
		path := strings.TrimPrefix(addr, "unix:")
		if i := strings.IndexByte(path, ':'); i > 0 {
			path = path[:i]
		}
		if !strings.HasPrefix(path, "/") {
			return backendTarget{}, false
		}
		return backendTarget{unix: path}, true
	}
	if strings.HasPrefix(addr, "/") {
		return backendTarget{unix: addr}, true
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		host = strings.Trim(addr, "[]")
		switch scheme {
		case "http", "grpc":
			portStr = "80"
		case "https", "grpcs":
			portStr = "443"
		default:
			return backendTarget{}, false
		}
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 || host == "" {
		return backendTarget{}, false
	}
	return backendTarget{host: strings.ToLower(host), port: port}, true
}

func backendLocal(host string, own map[string]bool) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1", "0.0.0.0", "::":
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || own[ip.String()]
	}
	return false
}

type backendState struct {
	gone     bool
	down     string
	upstream string
}

func judgeBackends(passes [][2]string, upstreams map[string][]string, own map[string]bool, ports map[int]ListenPort, unitOf func(int) string, answers func(string) bool) (backendState, bool) {
	var st backendState
	known := false
	for _, dp := range passes {
		targets, ok := backendTargets(dp[0], dp[1], upstreams)
		if !ok {
			continue
		}
		local := true
		for _, t := range targets {
			if t.unix == "" && !backendLocal(t.host, own) {
				local = false
				break
			}
		}
		if !local {
			continue
		}
		judged, alive := false, false
		var dead []string
		for _, t := range targets {
			if t.unix != "" {
				judged = true
				if _, err := os.Stat(t.unix); err == nil {
					alive = true
				} else if os.IsNotExist(err) {
					dead = append(dead, t.String())
				}
				continue
			}
			if len(ports) == 0 {
				continue
			}
			judged = true
			lp, listening := ports[t.port]
			if !listening {
				if answers(t.String()) {
					alive = true
				} else {
					dead = append(dead, t.String())
				}
				continue
			}
			alive = true
			if st.upstream == "" && lp.Process != "" && dp[0] != "fastcgi_pass" {
				desc := lp.Process
				if unit := unitOf(lp.Pid); unit != "" {
					desc += " (" + unit + ")"
				}
				st.upstream = fmt.Sprintf("%s :%d", desc, t.port)
			}
		}
		if !judged {
			continue
		}
		known = true
		if !alive && len(dead) > 0 && st.down == "" {
			st.gone = true
			st.down = strings.Join(dead, ", ")
		}
	}
	return st, known
}

func localAnswers(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func pidUnit(pid int) string {
	if pid <= 0 {
		return ""
	}
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return ""
	}
	unit := ""
	for _, line := range strings.Split(string(b), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		for _, seg := range strings.Split(parts[2], "/") {
			if strings.HasSuffix(seg, ".service") && !strings.HasPrefix(seg, "user@") {
				unit = seg
			}
		}
		if unit != "" {
			return unit
		}
	}
	return unit
}

func vhostBackendStates(service string) map[string]backendState {
	v, ok := vhostPoolsCache.Load(service)
	if !ok {
		return nil
	}
	scanByName, _ := v.(map[string]vhostScanInfo)
	if len(scanByName) == 0 {
		return nil
	}
	var upstreams map[string][]string
	if u, ok := vhostUpstreamsCache.Load(service); ok {
		upstreams, _ = u.(map[string][]string)
	}
	own := hostAddrSet()
	ports := currentListenPorts()
	out := map[string]backendState{}
	for name, scan := range scanByName {
		if st, known := judgeBackends(scan.passes, upstreams, own, ports, pidUnit, localAnswers); known {
			out[name] = st
		}
	}
	return out
}
