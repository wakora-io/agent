package defs

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"wakora.io/agent/internal/apm"
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

	autostage := p.Options["autostage"] == "1"
	endpoint := p.Options["otelEndpoint"]
	if endpoint == "" {
		endpoint = "http://127.0.0.1:4318"
	}
	register := filepath.Join(stateDir, "apm", nodeBundle, "wakora-register.js")
	anyActive := false
	for i, m := range masters {
		label := nodeStageLabel(m, i)
		key := "stage." + label
		if len(masters) == 1 {
			key = "otelStage"
		}
		environ, envErr := os.ReadFile("/proc/" + strconv.Itoa(m.pid) + "/environ")
		active := envErr == nil && apm.NodeEnvActive(string(environ))
		stageID := "apmnode-" + service + "-" + label
		inst := 0.0
		if active {
			inst = 1
		}
		o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: "svc." + service + ".instrumented", Value: inst, Tags: map[string]string{"unit": label}})
		if active {
			anyActive = true
			o.Facts[key] = "active"
			if apm.StagedState(stateDir, stageID) == "pending_activation" {
				_ = apm.MarkActivated(stateDir, stageID)
				o.Events = append(o.Events, apmEvent("apm_activated", map[string]string{"service": service, "layer": "node-otel", "unit": label}))
			}
			if autostage && p.Options["autoprovision"] == "1" && Provision != nil {
				if Provision.NeedsRefresh(nodeBundle) {
					Provision.Ensure(nodeBundle, true)
					o.Facts[key] = "active (fetching new signed build)"
				} else if sha := Provision.LocalSha(nodeBundle); sha != "" && sha != stagedArtifactSha(stateDir, stageID) && !stagingDenied.Load() && strings.HasPrefix(m.launch, "systemd:") {
					stageNode(o, service, stateDir, m, label, key, stageID, register, endpoint, sha)
					o.Facts[key] = "active (new build staged; restart to apply)"
				}
			}
			continue
		}
		if envErr == nil && apm.StagedState(stateDir, stageID) == "active" {
			_ = apm.ResetStaged(stateDir, stageID)
			o.Events = append(o.Events, apmEvent("apm_deactivated", map[string]string{"service": service, "layer": "node-otel", "unit": label}))
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
		if !nodeVersionOK(m.version) {
			o.Facts[key] = "blocked: node " + m.version + " (spans need >= 18.19)"
			continue
		}
		if !strings.HasPrefix(m.launch, "systemd:") {
			o.Facts[key] = "unsupported launch: " + m.launch + " (systemd services only for now)"
			continue
		}
		if _, err := os.Stat(filepath.Join(stateDir, "apm", nodeBundle)); err != nil {
			continue
		}
		sha := ""
		if Provision != nil {
			sha = Provision.LocalSha(nodeBundle)
		}
		stageNode(o, service, stateDir, m, label, key, stageID, register, endpoint, sha)
	}
	if anyActive || autostage {
		ensureOTLPFor(p.Options["otelEndpoint"])
	}
}

func stageNode(o *Outcome, service, stateDir string, m nodeMaster, label, key, stageID, register, endpoint, sha string) {
	unit := strings.TrimPrefix(m.launch, "systemd:")
	env := apm.NodeEnv(register, label, endpoint)
	content := nodeDropin(env, sha)
	stagedPath := filepath.Join(stateDir, "staged", stageID+".staged")
	dst := "/etc/systemd/system/" + unit + ".d/10-wakora-otel.conf"
	command := "mkdir -p /etc/systemd/system/" + unit + ".d && " +
		"{ [ ! -e " + dst + " ] || cp -a " + dst + " " + dst + ".wakora-prev; } && cp " +
		stagedPath + " " + dst +
		" && systemctl daemon-reload && systemctl restart " + unit
	change := apm.StagedChange{ID: stageID, Service: service, Kind: "node-otel", Impact: "restart", Command: command}
	staged, isNew, err := apm.Stage(stateDir, change, []byte(content))
	if err != nil {
		o.Facts[key] = "stage failed: " + err.Error()
		return
	}
	o.Facts[key] = staged.State
	if isNew {
		o.Events = append(o.Events, apmEvent("action_required", map[string]string{
			"service": service, "change": "node-otel", "impact": "restart",
			"command": staged.Command, "stagedPath": staged.StagedPath, "unit": label, "host": "systemd",
		}))
	}
}

var nodeEnvOrder = []string{"NODE_OPTIONS", "OTEL_SERVICE_NAME", "OTEL_EXPORTER_OTLP_ENDPOINT"}

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

func nodeStageLabel(m nodeMaster, i int) string {
	if u, ok := strings.CutPrefix(m.launch, "systemd:"); ok {
		return strings.TrimSuffix(u, ".service")
	}
	if strings.HasPrefix(m.launch, "pm2:") {
		return "pm2"
	}
	if i == 0 {
		return "bare"
	}
	return "bare-" + strconv.Itoa(i+1)
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
