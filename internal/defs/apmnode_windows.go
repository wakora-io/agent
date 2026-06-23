//go:build windows

package defs

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/yusufpapurcu/wmi"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"wakora.io/agent/internal/apm"
	"wakora.io/agent/internal/protocol"
)

type win32NodeProcess struct {
	ProcessId       uint32
	ParentProcessId uint32
	CommandLine     *string
	ExecutablePath  *string
}

func runAPMNodeWindows(o *Outcome, service string, p protocol.Probe, stateDir string) {
	proc := p.Process
	if proc == "" {
		proc = "node"
	}
	var procs []win32NodeProcess
	if err := wmi.Query("SELECT ProcessId, ParentProcessId, CommandLine, ExecutablePath FROM Win32_Process WHERE Name='"+proc+".exe'", &procs); err != nil {
		o.Check.Status = "fail"
		o.Check.Error = "wmi: " + err.Error()
		return
	}
	o.Check.Target = "node"
	if len(procs) == 0 {
		o.Check.Status = "fail"
		o.Check.Error = "no " + proc + ".exe processes"
		return
	}
	svcByPid, svcRunning := winServicePids()
	seen := map[string]bool{}
	var masters []nodeMaster
	for _, wp := range procs {
		exe := ""
		if wp.ExecutablePath != nil {
			exe = *wp.ExecutablePath
		}
		cmd := ""
		if wp.CommandLine != nil {
			cmd = *wp.CommandLine
		}
		app := winNodeAppOf(cmd)
		launch := "bare"
		if name, ok := svcByPid[wp.ProcessId]; ok {
			launch = "service:" + name
		} else if name, ok := svcByPid[wp.ParentProcessId]; ok {
			launch = "service:" + name
		}
		key := exe + "|" + app + "|" + launch
		if seen[key] {
			continue
		}
		seen[key] = true
		masters = append(masters, nodeMaster{pid: int(wp.ProcessId), exe: exe, app: app, launch: launch})
		if len(masters) >= 5 {
			break
		}
	}
	if len(masters) == 0 {
		o.Check.Status = "fail"
		o.Check.Error = "no " + proc + ".exe processes"
		return
	}
	sort.Slice(masters, func(i, j int) bool {
		si := strings.HasPrefix(masters[i].launch, "service:")
		sj := strings.HasPrefix(masters[j].launch, "service:")
		if si != sj {
			return si
		}
		if masters[i].launch != masters[j].launch {
			return masters[i].launch < masters[j].launch
		}
		return masters[i].app < masters[j].app
	})
	for i := range masters {
		masters[i].version = nodeVersionOf(masters[i].exe)
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
	targets := winNodeTargets(masters)
	anyActive := false
	for _, t := range targets {
		key := "stage." + t.label
		if len(targets) == 1 {
			key = "otelStage"
		}
		if t.unit != "" && svcRunning != nil {
			up := 0.0
			if svcRunning[t.unit] {
				up = 1
			}
			o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: "svc." + service + ".up", Value: up, Tags: map[string]string{"unit": t.label}})
		}
		o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: "svc." + service + ".restarts_seen", Value: nodeRestartsSeen(t), Tags: map[string]string{"unit": t.label}})
		stageID := "apmnode-" + service + "-" + t.label
		if t.unit == "" {
			o.Facts[key] = "unsupported launch: " + t.launch
			o.Facts["bareRecipe"] = "$env:NODE_OPTIONS='--require " + register + "'; $env:OTEL_EXPORTER_OTLP_ENDPOINT='" + endpoint + "'; node <app>"
			continue
		}
		envLines := winServiceEnv(t.unit)
		applied := false
		existing := ""
		for _, ln := range envLines {
			if strings.HasPrefix(ln, "NODE_OPTIONS=") {
				val := strings.TrimPrefix(ln, "NODE_OPTIONS=")
				if strings.Contains(val, "wakora-register.js") {
					applied = true
				} else {
					existing = val
				}
			}
		}
		if applied {
			anyActive = true
			o.Facts[key] = "active"
			if apm.StagedState(stateDir, stageID) == "pending_activation" {
				_ = apm.MarkActivated(stateDir, stageID)
				o.Events = append(o.Events, apmEvent("apm_activated", map[string]string{"service": service, "layer": "node-otel", "unit": t.label}))
			}
			continue
		}
		if apm.StagedState(stateDir, stageID) == "active" {
			_ = apm.ResetStaged(stateDir, stageID)
			o.Events = append(o.Events, apmEvent("apm_deactivated", map[string]string{"service": service, "layer": "node-otel", "unit": t.label}))
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
		if _, err := os.Stat(filepath.Join(stateDir, "apm", nodeBundle)); err != nil {
			continue
		}
		sha := ""
		if Provision != nil {
			sha = Provision.LocalSha(nodeBundle)
		}
		stageWinNodeTarget(o, service, stateDir, t, key, stageID, register, endpoint, sha, existing)
	}
	if anyActive || autostage {
		ensureOTLPFor(p.Options["otelEndpoint"])
	}
}

func winNodeTargets(masters []nodeMaster) []nodeTarget {
	var out []nodeTarget
	idx := map[string]int{}
	for _, m := range masters {
		if name, ok := strings.CutPrefix(m.launch, "service:"); ok {
			if i, found := idx[name]; found {
				out[i].masters = append(out[i].masters, m)
				continue
			}
			idx[name] = len(out)
			out = append(out, nodeTarget{label: name, unit: name, launch: m.launch, masters: []nodeMaster{m}})
			continue
		}
		if i, found := idx["bare"]; found {
			out[i].masters = append(out[i].masters, m)
			continue
		}
		idx["bare"] = len(out)
		out = append(out, nodeTarget{label: "bare", launch: m.launch, masters: []nodeMaster{m}})
	}
	return out
}

func stageWinNodeTarget(o *Outcome, service, stateDir string, t nodeTarget, key, stageID, register, endpoint, sha, existing string) {
	env := apm.NodeEnv(register, t.label, endpoint, existing, false)
	stagedPath := filepath.Join(stateDir, "staged", stageID+".staged")
	content := winNodeEnvScript(t.unit, env, sha)
	command := "powershell -ExecutionPolicy Bypass -Command \"& ([scriptblock]::Create((Get-Content -Raw '" + stagedPath + "')))\""
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
			"command": staged.Command, "stagedPath": staged.StagedPath, "unit": t.label, "host": "windows-service",
		}
		if existing != "" {
			det["merged"] = existing
		}
		o.Events = append(o.Events, apmEvent("action_required", det))
	}
}

func winNodeEnvScript(svcName string, env map[string]string, sha string) string {
	var b strings.Builder
	if sha != "" {
		fmt.Fprintf(&b, "# wakora-artifact-sha %s\n", sha)
	}
	fmt.Fprintf(&b, "$svc = '%s'\n", svcName)
	b.WriteString("$key = \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$svc\"\n")
	b.WriteString("$prev = (Get-ItemProperty -Path $key -Name Environment -ErrorAction SilentlyContinue).Environment\n")
	b.WriteString("$mine = @(\n")
	first := true
	for _, k := range nodeEnvOrder {
		if v := env[k]; v != "" {
			if !first {
				b.WriteString(",\n")
			}
			fmt.Fprintf(&b, "'%s=%s'", k, v)
			first = false
		}
	}
	b.WriteString("\n)\n")
	b.WriteString("$keep = @()\n")
	b.WriteString("if ($prev) { $keep = @($prev | Where-Object { ($_ -notmatch '^NODE_OPTIONS=') -and ($_ -notmatch '^OTEL_') }) }\n")
	b.WriteString("Set-ItemProperty -Path $key -Name Environment -Value ([string[]]($keep + $mine)) -Type MultiString\n")
	b.WriteString("try {\n")
	b.WriteString("  Restart-Service -Name $svc -Force -ErrorAction Stop\n")
	b.WriteString("  Write-Host \"wakora: node otel activated on service $svc\"\n")
	b.WriteString("} catch {\n")
	b.WriteString("  if ($prev) { Set-ItemProperty -Path $key -Name Environment -Value $prev -Type MultiString } else { Remove-ItemProperty -Path $key -Name Environment -ErrorAction SilentlyContinue }\n")
	b.WriteString("  Restart-Service -Name $svc -Force -ErrorAction SilentlyContinue\n")
	b.WriteString("  Write-Host 'wakora: node activation failed - environment reverted, service restarted clean'\n")
	b.WriteString("  exit 1\n")
	b.WriteString("}\n")
	return b.String()
}

func winServicePids() (map[uint32]string, map[string]bool) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, nil
	}
	defer m.Disconnect()
	names, err := m.ListServices()
	if err != nil {
		return nil, nil
	}
	pids := map[uint32]string{}
	running := map[string]bool{}
	for _, n := range names {
		s, err := m.OpenService(n)
		if err != nil {
			continue
		}
		st, err := s.Query()
		s.Close()
		if err != nil {
			continue
		}
		running[n] = st.State == svc.Running
		if st.ProcessId != 0 {
			pids[uint32(st.ProcessId)] = n
		}
	}
	return pids, running
}

func winServiceEnv(name string) []string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+name, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	v, _, err := k.GetStringsValue("Environment")
	if err != nil {
		return nil
	}
	return v
}

func winNodeAppOf(cmdline string) string {
	if cmdline == "" {
		return ""
	}
	args, err := windows.DecomposeCommandLine(cmdline)
	if err != nil || len(args) < 2 {
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
