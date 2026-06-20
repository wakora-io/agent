package defs

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"wakora.io/agent/internal/protocol"
)

const nodeBundle = "opentelemetry-node"

type nodeMaster struct {
	pid     int
	exe     string
	app     string
	version string
	launch  string
}

var nodeVersionRe = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)`)
var nodeVerCache = map[string]string{}

func RunAPMNode(service string, p protocol.Probe, stateDir string) (o Outcome) {
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
	runAPMNode(&o, service, p, stateDir)
	o.Check.LatencyMs = float64(time.Since(start).Microseconds()) / 1000
	return o
}

func runAPMNode(o *Outcome, service string, p protocol.Probe, stateDir string) {
	if runtime.GOOS != "linux" {
		o.Check.Status = "fail"
		o.Check.Error = "node apm is linux-only for now"
		return
	}
	proc := p.Process
	if proc == "" {
		proc = "node"
	}
	masters := nodeMasters(proc)
	o.Check.Target = "node"
	if len(masters) == 0 {
		o.Check.Status = "fail"
		o.Check.Error = "no " + proc + " processes outside containers"
		return
	}
	o.Check.Status = "ok"
	prim := masters[0]
	o.Facts = map[string]string{
		"binary":      prim.exe,
		"app":         prim.app,
		"nodeVersion": prim.version,
		"launch":      prim.launch,
		"masters":     strconv.Itoa(len(masters)),
	}
	runtimeOk := "0"
	for _, m := range masters {
		if nodeVersionOK(m.version) {
			runtimeOk = "1"
		}
	}
	o.Facts["runtimeOk"] = runtimeOk
	for i, m := range masters {
		if i == 0 {
			continue
		}
		o.Facts["master."+strconv.Itoa(i+1)] = m.launch + " " + m.app + " v" + m.version
	}
	o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: "svc." + service + ".masters", Value: float64(len(masters))})

	if p.Options["autoprovision"] == "1" && Provision != nil {
		bundleDir := filepath.Join(stateDir, "apm", nodeBundle)
		if _, err := os.Stat(bundleDir); err != nil {
			o.Facts["artifact"] = Provision.Ensure(nodeBundle, true)
		} else if Provision.NeedsRefresh(nodeBundle) {
			o.Facts["artifact"] = "refreshing: " + Provision.Ensure(nodeBundle, true)
		} else {
			o.Facts["artifact"] = "ready"
		}
	} else {
		o.Facts["artifact"] = "artifact required: " + nodeBundle + " (OTel Node.js bundle)"
	}
}

func nodeMasters(proc string) []nodeMaster {
	out, err := exec.Command("pgrep", "-x", proc).Output()
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var ms []nodeMaster
	for _, f := range strings.Fields(string(out)) {
		pid, err := strconv.Atoi(f)
		if err != nil {
			continue
		}
		cg, _ := os.ReadFile("/proc/" + f + "/cgroup")
		if nodeInContainer(string(cg)) {
			continue
		}
		exe, _ := os.Readlink("/proc/" + f + "/exe")
		if exe == "" {
			continue
		}
		app := nodeAppOf("/proc/" + f + "/cmdline")
		key := exe + "|" + app
		if seen[key] {
			continue
		}
		seen[key] = true
		ms = append(ms, nodeMaster{pid: pid, exe: exe, app: app, launch: nodeLaunchOf(string(cg))})
		if len(ms) >= 5 {
			break
		}
	}
	for i := range ms {
		ms[i].version = nodeVersionOf(ms[i].exe)
	}
	return ms
}

func nodeInContainer(cgroup string) bool {
	for _, marker := range []string{"docker-", "/docker/", "libpod-", "kubepods", "cri-containerd", "/lxc/", "lxc.payload"} {
		if strings.Contains(cgroup, marker) {
			return true
		}
	}
	return false
}

func nodeLaunchOf(cgroup string) string {
	for _, line := range strings.Split(strings.TrimSpace(cgroup), "\n") {
		i := strings.LastIndexByte(line, ':')
		if i < 0 {
			continue
		}
		path := line[i+1:]
		base := path[strings.LastIndexByte(path, '/')+1:]
		if strings.HasSuffix(base, ".service") {
			if strings.HasPrefix(base, "pm2-") || base == "pm2.service" {
				return "pm2:" + base
			}
			return "systemd:" + base
		}
		if strings.Contains(path, "/user.slice") || strings.Contains(path, "/session-") {
			return "bare"
		}
	}
	return "bare"
}

func nodeAppOf(cmdlinePath string) string {
	raw, err := os.ReadFile(cmdlinePath)
	if err != nil {
		return ""
	}
	args := strings.Split(string(raw), "\x00")
	if len(args) < 2 {
		return ""
	}
	for _, a := range args[1:] {
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		return a
	}
	return ""
}

func nodeVersionOf(exe string) string {
	key := exe
	if st, err := os.Stat(exe); err == nil {
		key = exe + "|" + strconv.FormatInt(st.Size(), 10) + "|" + strconv.FormatInt(st.ModTime().UnixNano(), 10)
	}
	if v, ok := nodeVerCache[key]; ok {
		return v
	}
	v := ""
	if out, err := exec.Command(exe, "--version").Output(); err == nil {
		v = strings.TrimPrefix(strings.TrimSpace(string(out)), "v")
	}
	if len(nodeVerCache) > 64 {
		nodeVerCache = map[string]string{}
	}
	nodeVerCache[key] = v
	return v
}

func nodeVersionOK(v string) bool {
	m := nodeVersionRe.FindStringSubmatch(v)
	if m == nil {
		return false
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	return major > 18 || (major == 18 && minor >= 19)
}
