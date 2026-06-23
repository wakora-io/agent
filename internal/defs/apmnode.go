package defs

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"wakora.io/agent/internal/apm"
	"wakora.io/agent/internal/protocol"
)

const nodeBundle = "opentelemetry-node"

var nodeProfileAllowed atomic.Bool

func SetNodeProfileAllowed(v bool) { nodeProfileAllowed.Store(v) }

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

	autostage := p.Options["autostage"] == "1"
	endpoint := p.Options["otelEndpoint"]
	if endpoint == "" {
		endpoint = "http://127.0.0.1:4318"
	}
	register := filepath.Join(stateDir, "apm", nodeBundle, "wakora-register.js")
	profile := p.Options["profile"] == "1" || nodeProfileAllowed.Load()
	targets := nodeTargets(masters)
	anyActive := false
	for _, t := range targets {
		if t.perApp {
			errL, outL := pm2LogFiles(t.masters)
			if errL != "" {
				o.Facts["pm2LogsErr"] = errL
			}
			if outL != "" {
				o.Facts["pm2LogsOut"] = outL
			}
		}
		if u, ok := strings.CutPrefix(t.launch, "systemd:"); ok {
			if up, crashes, stateOk := nodeUnitState(u); stateOk {
				o.Metrics = append(o.Metrics,
					protocol.MetricPoint{Name: "svc." + service + ".up", Value: up, Tags: map[string]string{"unit": t.label}},
					protocol.MetricPoint{Name: "svc." + service + ".crash_restarts", Value: crashes, Tags: map[string]string{"unit": t.label}})
			}
		}
		o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: "svc." + service + ".restarts_seen", Value: nodeRestartsSeen(t), Tags: map[string]string{"unit": t.label}})
		key := "stage." + t.label
		if len(targets) == 1 {
			key = "otelStage"
		}
		stageID := "apmnode-" + service + "-" + t.label
		activeN := 0
		detectOk := false
		existing := ""
		for _, m := range t.masters {
			environ, envErr := os.ReadFile("/proc/" + strconv.Itoa(m.pid) + "/environ")
			if envErr != nil {
				continue
			}
			detectOk = true
			if apm.NodeEnvActive(string(environ)) {
				activeN++
			} else if existing == "" {
				existing = nodeExistingOptions(string(environ))
			}
		}
		o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: "svc." + service + ".instrumented", Value: float64(activeN) / float64(len(t.masters)), Tags: map[string]string{"unit": t.label}})
		if detectOk && activeN == len(t.masters) {
			anyActive = true
			o.Facts[key] = "active"
			if apm.StagedState(stateDir, stageID) == "pending_activation" {
				_ = apm.MarkActivated(stateDir, stageID)
				o.Events = append(o.Events, apmEvent("apm_activated", map[string]string{"service": service, "layer": "node-otel", "unit": t.label}))
			}
			if autostage && p.Options["autoprovision"] == "1" && Provision != nil {
				if Provision.NeedsRefresh(nodeBundle) {
					Provision.Ensure(nodeBundle, true)
					o.Facts[key] = "active (fetching new signed build)"
				} else if sha := Provision.LocalSha(nodeBundle); sha != "" && sha != stagedArtifactSha(stateDir, stageID) && !stagingDenied.Load() && t.unit != "" {
					stageNodeTarget(o, service, stateDir, t, key, stageID, register, endpoint, sha, "", profile)
					o.Facts[key] = "active (new build staged; restart to apply)"
				}
			}
			continue
		}
		if detectOk && activeN == 0 && apm.StagedState(stateDir, stageID) == "active" {
			_ = apm.ResetStaged(stateDir, stageID)
			o.Events = append(o.Events, apmEvent("apm_deactivated", map[string]string{"service": service, "layer": "node-otel", "unit": t.label}))
		}
		if activeN > 0 {
			o.Facts[key] = fmt.Sprintf("partial: %d/%d instrumented", activeN, len(t.masters))
			continue
		}
		if !autostage {
			continue
		}
		if stagingDenied.Load() {
			if apm.StagedState(stateDir, stageID) == "pending_activation" {
				_ = apm.ResetStaged(stateDir, stageID)
			}
			o.Facts[key] = "disabled from the console"
			continue
		}
		verBad := ""
		for _, m := range t.masters {
			if !nodeVersionOK(m.version) {
				verBad = m.version
				break
			}
		}
		if verBad != "" {
			o.Facts[key] = "blocked: node " + verBad + " (spans need >= 18.19)"
			continue
		}
		if t.unit == "" {
			o.Facts[key] = "unsupported launch: " + t.launch
			o.Facts["bareRecipe"] = "NODE_OPTIONS=\"--require " + register + "\" OTEL_EXPORTER_OTLP_ENDPOINT=\"" + endpoint + "\""
			continue
		}
		if _, err := os.Stat(filepath.Join(stateDir, "apm", nodeBundle)); err != nil {
			continue
		}
		sha := ""
		if Provision != nil {
			sha = Provision.LocalSha(nodeBundle)
		}
		stageNodeTarget(o, service, stateDir, t, key, stageID, register, endpoint, sha, existing, profile)
	}
	if anyActive || autostage {
		ensureOTLPFor(p.Options["otelEndpoint"])
	}
}

type nodeTarget struct {
	label   string
	unit    string
	launch  string
	perApp  bool
	masters []nodeMaster
}

func nodeTargets(masters []nodeMaster) []nodeTarget {
	var out []nodeTarget
	idx := map[string]int{}
	add := func(gk string, t nodeTarget, m nodeMaster) {
		if i, ok := idx[gk]; ok {
			out[i].masters = append(out[i].masters, m)
			return
		}
		idx[gk] = len(out)
		t.masters = []nodeMaster{m}
		out = append(out, t)
	}
	for _, m := range masters {
		if u, ok := strings.CutPrefix(m.launch, "systemd:"); ok {
			add("s:"+u, nodeTarget{label: strings.TrimSuffix(u, ".service"), unit: u, launch: m.launch}, m)
			continue
		}
		if u, ok := strings.CutPrefix(m.launch, "pm2:"); ok {
			add("pm2", nodeTarget{label: "pm2", unit: u, launch: m.launch, perApp: true}, m)
			continue
		}
		add("bare", nodeTarget{label: "bare", launch: m.launch}, m)
	}
	return out
}

func pm2LogFiles(masters []nodeMaster) (string, string) {
	home := ""
	for _, m := range masters {
		environ, err := os.ReadFile("/proc/" + strconv.Itoa(m.pid) + "/environ")
		if err != nil {
			continue
		}
		for _, kv := range strings.Split(string(environ), "\x00") {
			if v, ok := strings.CutPrefix(kv, "PM2_HOME="); ok && v != "" {
				home = v
				break
			}
			if v, ok := strings.CutPrefix(kv, "HOME="); ok && home == "" && v != "" {
				home = filepath.Join(v, ".pm2")
			}
		}
		if home != "" {
			break
		}
	}
	if home == "" {
		home = "/root/.pm2"
	}
	entries, err := os.ReadDir(filepath.Join(home, "logs"))
	if err != nil {
		return "", ""
	}
	var errL, outL []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".log") {
			continue
		}
		full := filepath.Join(home, "logs", e.Name())
		if strings.HasSuffix(e.Name(), "-error.log") {
			if len(errL) < 20 {
				errL = append(errL, full)
			}
		} else if len(outL) < 20 {
			outL = append(outL, full)
		}
	}
	return strings.Join(errL, ","), strings.Join(outL, ",")
}

func nodeUnitState(unit string) (up, crashes float64, ok bool) {
	out, err := exec.Command("systemctl", "show", "-p", "ActiveState,NRestarts", unit).Output()
	if err != nil {
		log.Printf("apmnode: systemctl show %s: %v", unit, err)
		return 0, 0, false
	}
	seen := false
	for _, line := range strings.Split(string(out), "\n") {
		if v, found := strings.CutPrefix(line, "ActiveState="); found {
			seen = true
			if strings.TrimSpace(v) == "active" {
				up = 1
			}
		}
		if v, found := strings.CutPrefix(line, "NRestarts="); found {
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				crashes = float64(n)
			}
		}
	}
	if !seen {
		log.Printf("apmnode: systemctl show %s returned no ActiveState", unit)
	}
	return up, crashes, seen
}

var nodePrevPids = map[string]string{}
var nodeRestartCounts = map[string]float64{}

func nodeRestartsSeen(t nodeTarget) float64 {
	pids := make([]string, 0, len(t.masters))
	for _, m := range t.masters {
		pids = append(pids, strconv.Itoa(m.pid))
	}
	sort.Strings(pids)
	sig := strings.Join(pids, ",")
	prev, seen := nodePrevPids[t.label]
	if seen && prev != sig {
		nodeRestartCounts[t.label]++
	}
	nodePrevPids[t.label] = sig
	return nodeRestartCounts[t.label]
}

func nodeExistingOptions(environ string) string {
	for _, kv := range strings.Split(environ, "\x00") {
		if v, ok := strings.CutPrefix(kv, "NODE_OPTIONS="); ok {
			if strings.Contains(v, "wakora-register.js") {
				return ""
			}
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func stageNodeTarget(o *Outcome, service, stateDir string, t nodeTarget, key, stageID, register, endpoint, sha, existing string, perf bool) {
	svcName := t.label
	if t.perApp {
		svcName = ""
	}
	env := apm.NodeEnv(register, svcName, endpoint, existing, perf)
	stagedPath := filepath.Join(stateDir, "staged", stageID+".staged")
	var content, command string
	if t.perApp {
		content = nodeEnvFile(env, sha)
		command = "set -a; . " + stagedPath + "; set +a; pm2 restart all --update-env && pm2 save || { " +
			"export NODE_OPTIONS=\"" + existing + "\" OTEL_EXPORTER_OTLP_ENDPOINT=; pm2 restart all --update-env; pm2 save; " +
			"echo 'wakora: pm2 activation failed - env reverted, apps restarted clean'; false; }"
	} else {
		content = nodeDropin(env, sha)
		dst := "/etc/systemd/system/" + t.unit + ".d/10-wakora-otel.conf"
		bdir := "/var/lib/wakora/backups/node-" + t.label + "-$(date +%Y%m%d-%H%M%S)"
		command = "B=" + bdir + " && mkdir -p $B /etc/systemd/system/" + t.unit + ".d && " +
			"{ [ ! -e " + dst + " ] || cp -a " + dst + " $B/; } && cp " +
			stagedPath + " " + dst +
			" && systemctl daemon-reload && systemctl restart " + t.unit + " || { " +
			"rm -f " + dst + "; [ ! -e $B/10-wakora-otel.conf ] || cp -a $B/10-wakora-otel.conf " + dst + "; " +
			"systemctl daemon-reload; systemctl restart " + t.unit + "; " +
			"echo \"wakora: node activation failed - dropin reverted, original restored from $B\"; false; }"
	}
	change := apm.StagedChange{ID: stageID, Service: service, Kind: "node-otel", Impact: "restart", Command: command}
	staged, isNew, err := apm.Stage(stateDir, change, []byte(content))
	if err != nil {
		o.Facts[key] = "stage failed: " + err.Error()
		return
	}
	o.Facts[key] = staged.State
	if isNew {
		det := map[string]string{
			"service": service, "change": "node-otel", "impact": "restart",
			"command": staged.Command, "stagedPath": staged.StagedPath, "unit": t.label, "host": "systemd",
		}
		if t.perApp {
			det["host"] = "pm2"
			det["scope"] = strconv.Itoa(len(t.masters)) + " pm2 apps restart together"
		}
		if existing != "" {
			det["merged"] = existing
		}
		o.Events = append(o.Events, apmEvent("action_required", det))
	}
}

var nodeEnvOrder = []string{"NODE_OPTIONS", "OTEL_SERVICE_NAME", "OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_TRACES_EXPORTER", "OTEL_METRICS_EXPORTER"}

func nodeDropin(env map[string]string, sha string) string {
	var b strings.Builder
	b.WriteString("[Service]\n")
	if sha != "" {
		fmt.Fprintf(&b, "# wakora-artifact-sha %s\n", sha)
	}
	for _, k := range nodeEnvOrder {
		if v := env[k]; v != "" {
			fmt.Fprintf(&b, "Environment=\"%s=%s\"\n", k, v)
		}
	}
	return b.String()
}

func nodeEnvFile(env map[string]string, sha string) string {
	var b strings.Builder
	if sha != "" {
		fmt.Fprintf(&b, "# wakora-artifact-sha %s\n", sha)
	}
	for _, k := range nodeEnvOrder {
		if v := env[k]; v != "" {
			fmt.Fprintf(&b, "%s=\"%s\"\n", k, v)
		}
	}
	return b.String()
}

func nodeMasters(proc string) []nodeMaster {
	dirs, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var ms []nodeMaster
	for _, d := range dirs {
		pid, err := strconv.Atoi(d.Name())
		if err != nil {
			continue
		}
		exe, err := os.Readlink("/proc/" + d.Name() + "/exe")
		if err != nil || filepath.Base(exe) != proc {
			continue
		}
		raw, _ := os.ReadFile("/proc/" + d.Name() + "/cmdline")
		if strings.HasPrefix(string(raw), "PM2 ") {
			continue
		}
		cg, _ := os.ReadFile("/proc/" + d.Name() + "/cgroup")
		if nodeInContainer(string(cg)) {
			continue
		}
		app := nodeAppOf(string(raw))
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
	rank := func(l string) int {
		if strings.HasPrefix(l, "systemd:") {
			return 0
		}
		if strings.HasPrefix(l, "pm2:") {
			return 1
		}
		return 2
	}
	sort.Slice(ms, func(i, j int) bool {
		ri, rj := rank(ms[i].launch), rank(ms[j].launch)
		if ri != rj {
			return ri < rj
		}
		if ms[i].launch != ms[j].launch {
			return ms[i].launch < ms[j].launch
		}
		return ms[i].app < ms[j].app
	})
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

func nodeAppOf(cmdline string) string {
	args := strings.Split(cmdline, "\x00")
	if len(args) == 0 {
		return ""
	}
	if f := strings.Fields(args[0]); len(f) > 1 && len(args) < 3 && !strings.HasPrefix(f[1], "-") {
		return f[1]
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
