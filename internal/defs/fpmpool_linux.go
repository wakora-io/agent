//go:build linux

package defs

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"wakora.io/agent/internal/protocol"
)

const fpmPoolCap = 150

type fpmPoolStat struct {
	workers int
	blocked int
}

type fpmPoolLimit struct {
	listen      string
	maxChildren int
	mode        string
}

var fpmPoolConfGlobs = []string{
	"/etc/php/*/fpm/pool.d/*.conf",
	"/etc/opt/remi/php*/php-fpm.d/*.conf",
	"/etc/php-fpm.d/*.conf",
	"/etc/php*/php-fpm.d/*.conf",
}

func runFPMPool(o *Outcome, service string, p protocol.Probe) {
	census := fpmWorkerCensus("/proc")
	limits := fpmPoolLimits(fpmPoolConfGlobs)
	unixQ := unixListenBacklogs()
	tcpQ := tcpListenBacklogs("/proc/net/tcp", "/proc/net/tcp6")

	names := map[string]bool{}
	for n := range census {
		names[n] = true
	}
	for n := range limits {
		names[n] = true
	}
	ordered := make([]string, 0, len(names))
	for n := range names {
		ordered = append(ordered, n)
	}
	sort.Strings(ordered)
	if len(ordered) > fpmPoolCap {
		ordered = ordered[:fpmPoolCap]
	}

	workers := 0
	for _, name := range ordered {
		tags := map[string]string{"pool": name}
		st := census[name]
		workers += st.workers
		o.Metrics = append(o.Metrics,
			protocol.MetricPoint{Name: "svc." + service + ".pool.workers", Value: float64(st.workers), Tags: tags},
			protocol.MetricPoint{Name: "svc." + service + ".pool.blocked", Value: float64(st.blocked), Tags: tags},
		)
		lim, ok := limits[name]
		if !ok {
			continue
		}
		if lim.maxChildren > 0 {
			o.Metrics = append(o.Metrics, protocol.MetricPoint{
				Name: "svc." + service + ".pool.max_children", Value: float64(lim.maxChildren), Tags: tags,
			})
		}
		if lim.mode != "" {
			static := 0.0
			if lim.mode == "static" {
				static = 1
			}
			o.Metrics = append(o.Metrics, protocol.MetricPoint{
				Name: "svc." + service + ".pool.static", Value: static, Tags: tags,
			})
		}
		if q, ok := listenBacklog(lim.listen, unixQ, tcpQ); ok {
			o.Metrics = append(o.Metrics, protocol.MetricPoint{
				Name: "svc." + service + ".pool.backlog", Value: float64(q), Tags: tags,
			})
		}
	}
	o.Metrics = append(o.Metrics, protocol.MetricPoint{
		Name: "svc." + service + ".pools", Value: float64(len(ordered)),
	})
	o.Check.Status = "ok"
	o.Check.Target = fmt.Sprintf("php-fpm pools (%d pools, %d workers)", len(ordered), workers)
}

func fpmWorkerCensus(procRoot string) map[string]fpmPoolStat {
	out := map[string]fpmPoolStat{}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		cmdRaw, err := os.ReadFile(filepath.Join(procRoot, e.Name(), "cmdline"))
		if err != nil {
			continue
		}
		title := strings.TrimRight(string(cmdRaw), "\x00")
		title = strings.ReplaceAll(title, "\x00", " ")
		if !strings.HasPrefix(title, "php-fpm: pool ") {
			continue
		}
		pool := strings.TrimSpace(strings.TrimPrefix(title, "php-fpm: pool "))
		if pool == "" {
			continue
		}
		st := out[pool]
		st.workers++
		if statState(filepath.Join(procRoot, e.Name(), "stat")) == 'D' {
			st.blocked++
		}
		out[pool] = st
	}
	return out
}

func statState(path string) byte {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	close := strings.LastIndexByte(string(raw), ')')
	if close < 0 || close+2 >= len(raw) {
		return 0
	}
	rest := strings.TrimSpace(string(raw[close+1:]))
	if rest == "" {
		return 0
	}
	return rest[0]
}

func fpmPoolLimits(globs []string) map[string]fpmPoolLimit {
	out := map[string]fpmPoolLimit{}
	for _, g := range globs {
		files, _ := filepath.Glob(g)
		for _, f := range files {
			raw, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			parseFpmPoolConf(string(raw), out)
		}
	}
	return out
}

func parseFpmPoolConf(raw string, out map[string]fpmPoolLimit) {
	section := ""
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == ';' || line[0] == '#' {
			continue
		}
		if line[0] == '[' {
			if i := strings.IndexByte(line, ']'); i > 1 {
				section = strings.TrimSpace(line[1:i])
			}
			continue
		}
		if section == "" || section == "global" {
			continue
		}
		key, val, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if i := strings.Index(val, " ;"); i >= 0 {
			val = strings.TrimSpace(val[:i])
		}
		val = strings.ReplaceAll(val, "$pool", section)
		lim := out[section]
		switch key {
		case "listen":
			if lim.listen == "" {
				lim.listen = val
			}
		case "pm":
			if lim.mode == "" {
				lim.mode = val
			}
		case "pm.max_children":
			if n, err := strconv.Atoi(val); err == nil {
				lim.maxChildren += n
			}
		}
		out[section] = lim
	}
}

func listenBacklog(listen string, unixQ map[string]uint32, tcpQ map[int]uint32) (uint32, bool) {
	if listen == "" {
		return 0, false
	}
	if strings.HasPrefix(listen, "/") {
		q, ok := unixQ[listen]
		return q, ok
	}
	portStr := listen
	if i := strings.LastIndexByte(listen, ':'); i >= 0 {
		portStr = listen[i+1:]
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, false
	}
	q, ok := tcpQ[port]
	return q, ok
}

func unixListenBacklogs() map[string]uint32 {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return nil
	}
	defer unix.Close(fd)

	req := make([]byte, 40)
	ne := binary.NativeEndian
	ne.PutUint32(req[0:4], 40)
	ne.PutUint16(req[4:6], 20)
	ne.PutUint16(req[6:8], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	ne.PutUint32(req[8:12], 1)
	req[16] = unix.AF_UNIX
	ne.PutUint32(req[20:24], 1<<10)
	ne.PutUint32(req[28:32], 0x1|0x10)
	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil
	}

	out := map[string]uint32{}
	buf := make([]byte, 1<<16)
	for i := 0; i < 64; i++ {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil || n <= 0 {
			return out
		}
		done, err := parseUnixDiagDump(buf[:n], out)
		if err != nil || done {
			return out
		}
	}
	return out
}

func parseUnixDiagDump(buf []byte, out map[string]uint32) (bool, error) {
	ne := binary.NativeEndian
	for len(buf) >= 16 {
		msgLen := int(ne.Uint32(buf[0:4]))
		msgType := ne.Uint16(buf[4:6])
		if msgLen < 16 || msgLen > len(buf) {
			return true, fmt.Errorf("bad nlmsg length %d", msgLen)
		}
		if msgType == unix.NLMSG_DONE {
			return true, nil
		}
		if msgType == unix.NLMSG_ERROR {
			return true, fmt.Errorf("netlink error")
		}
		payload := buf[16:msgLen]
		if len(payload) >= 16 {
			state := payload[2]
			path := ""
			rq := uint32(0)
			hasRq := false
			attrs := payload[16:]
			for len(attrs) >= 4 {
				aLen := int(ne.Uint16(attrs[0:2]))
				aType := ne.Uint16(attrs[2:4])
				if aLen < 4 || aLen > len(attrs) {
					break
				}
				data := attrs[4:aLen]
				switch aType {
				case 0:
					if len(data) > 0 && data[0] != 0 {
						path = string(data[:len(data)-idxTrailingNul(data)])
					}
				case 4:
					if len(data) >= 8 {
						rq = ne.Uint32(data[0:4])
						hasRq = true
					}
				}
				attrs = attrs[nlaAlign(aLen):]
			}
			if state == 10 && path != "" && hasRq {
				out[path] = rq
			}
		}
		buf = buf[nlaAlign(msgLen):]
	}
	return false, nil
}

func idxTrailingNul(data []byte) int {
	if len(data) > 0 && data[len(data)-1] == 0 {
		return 1
	}
	return 0
}

func nlaAlign(n int) int {
	return (n + 3) &^ 3
}

func tcpListenBacklogs(paths ...string) map[int]uint32 {
	out := map[int]uint32{}
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		parseTCPListenBacklogs(string(raw), out)
	}
	return out
}

func parseTCPListenBacklogs(raw string, out map[int]uint32) {
	for _, line := range strings.Split(raw, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || f[3] != "0A" {
			continue
		}
		li := strings.LastIndexByte(f[1], ':')
		if li < 0 {
			continue
		}
		port64, err := strconv.ParseUint(f[1][li+1:], 16, 32)
		if err != nil {
			continue
		}
		qi := strings.IndexByte(f[4], ':')
		if qi < 0 {
			continue
		}
		rx64, err := strconv.ParseUint(f[4][qi+1:], 16, 32)
		if err != nil {
			continue
		}
		port := int(port64)
		if uint32(rx64) > out[port] {
			out[port] = uint32(rx64)
		}
	}
}
