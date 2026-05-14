package defs

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"wakora.io/agent/internal/apm"
	"wakora.io/agent/internal/protocol"
)

func apmEvent(kind string, detail map[string]string) protocol.AgentEvent {
	raw, _ := json.Marshal(detail)
	return protocol.AgentEvent{Kind: kind, Detail: string(raw)}
}

func stagedArtifactSha(stateDir, stageID string) string {
	data, err := os.ReadFile(filepath.Join(stateDir, "staged", stageID+".staged"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "; wakora-artifact-sha "); ok {
			return strings.TrimSpace(rest)
		}
		if rest, ok := strings.CutPrefix(line, "# wakora-artifact-sha "); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

func RunAPMDotnet(service string, p protocol.Probe, stateDir string) (o Outcome) {
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
	runAPMDotnet(&o, service, p, stateDir)
	o.Check.LatencyMs = float64(time.Since(start).Microseconds()) / 1000
	return o
}

func runAPMDotnet(o *Outcome, service string, p protocol.Probe, stateDir string) {
	osTag, arch, nativeSub := dotnetPlatform()
	bundle := apm.DotnetBundleName(osTag, arch)
	host := p.Options["host"]
	if host == "" {
		if runtime.GOOS == "windows" {
			host = "iis"
		} else {
			host = "systemd"
		}
	}

	loaded, pid, detectOk := dotnetInstrumented()
	if loaded || p.Options["autostage"] == "1" {
		ensureOTLPFor(p.Options["otelEndpoint"])
	}
	o.Check.Status = "ok"
	o.Check.Target = "dotnet/" + host
	instrumented := 0.0
	if loaded {
		instrumented = 1
	}
	o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: "svc." + service + ".instrumented", Value: instrumented})
	o.Facts = map[string]string{
		"dotnetHost": host,
		"arch":       arch,
		"osTag":      osTag,
		"otelBundle": bundle,
	}
	if pid > 0 {
		o.Facts["pid"] = strconv.Itoa(pid)
	}

	stageID := "apmdotnet-" + service
	autoprov := p.Options["autoprovision"] == "1" && Provision != nil
	if loaded {
		o.Facts["otelStage"] = "active"
		if apm.StagedState(stateDir, stageID) == "pending_activation" {
			_ = apm.MarkActivated(stateDir, stageID)
			o.Events = append(o.Events, apmEvent("apm_activated", map[string]string{"service": service, "layer": "dotnet-otel", "host": host}))
		}
		if autoprov && p.Options["autostage"] == "1" {
			if Provision.NeedsRefresh(bundle) {
				Provision.Ensure(bundle, true)
				o.Facts["otelStage"] = "active (fetching new signed build)"
			} else if sha := Provision.LocalSha(bundle); sha != "" && sha != stagedArtifactSha(stateDir, stageID) && !stagingDenied.Load() {
				stageDotnet(o, service, p, stateDir, bundle, nativeSub, host, stageID)
				o.Facts["otelStage"] = "active (new build staged; restart to apply)"
			}
		}
		return
	}
	if detectOk && apm.StagedState(stateDir, stageID) == "active" {
		_ = apm.ResetStaged(stateDir, stageID)
		o.Events = append(o.Events, apmEvent("apm_deactivated", map[string]string{
			"service": service, "layer": "dotnet-otel", "host": host,
		}))
	}
	if p.Options["autostage"] != "1" {
		return
	}
	if stagingDenied.Load() {
		if apm.StagedState(stateDir, stageID) == "pending_activation" {
			_ = apm.ResetStaged(stateDir, stageID)
		}
		o.Facts["otelStage"] = "disabled from the console"
		return
	}
	stageDotnet(o, service, p, stateDir, bundle, nativeSub, host, stageID)
}

func stageDotnet(o *Outcome, service string, p protocol.Probe, stateDir, bundle, nativeSub, host, stageID string) {
	if bundle == "" {
		o.Facts["otelStage"] = "blocked: unknown os/arch"
		return
	}
	autoprov := p.Options["autoprovision"] == "1" && Provision != nil
	bundleDir := filepath.Join(stateDir, "apm", bundle)
	if _, err := os.Stat(bundleDir); err != nil {
		if autoprov {
			o.Facts["otelStage"] = Provision.Ensure(bundle, true)
		} else {
			o.Facts["otelStage"] = "artifact required: " + bundle + " (OTel .NET auto-instrumentation bundle)"
		}
		return
	}
	if autoprov && Provision.NeedsRefresh(bundle) {
		o.Facts["otelStage"] = "refreshing: " + Provision.Ensure(bundle, true)
		return
	}
	endpoint := p.Options["otelEndpoint"]
	if endpoint == "" {
		endpoint = "http://127.0.0.1:4318"
	}
	native := filepath.Join(bundleDir, nativeSub, "OpenTelemetry.AutoInstrumentation.Native.so")
	if host == "iis" {
		native = filepath.Join(bundleDir, "win-x64", "OpenTelemetry.AutoInstrumentation.Native.dll")
	}
	env := apm.DotnetEnv(bundleDir, native, service, endpoint)
	sha := ""
	if autoprov {
		sha = Provision.LocalSha(bundle)
	}

	stagedPath := filepath.Join(stateDir, "staged", stageID+".staged")
	var content, command string
	switch host {
	case "iis":
		content = iisEnvScript(env, sha)
		command = "powershell -ExecutionPolicy Bypass -Command \"& ([scriptblock]::Create((Get-Content -Raw '" + stagedPath + "')))\""
	default:
		unit := p.Options["unit"]
		if unit == "" {
			unit = "kestrel"
		}
		content = systemdDropin(env, sha)
		dst := "/etc/systemd/system/" + unit + ".service.d/10-wakora-otel.conf"
		command = "mkdir -p /etc/systemd/system/" + unit + ".service.d && " +
			"{ [ ! -e " + dst + " ] || cp -a " + dst + " " + dst + ".wakora-prev; } && cp " +
			stagedPath + " " + dst +
			" && systemctl daemon-reload && systemctl restart " + unit
	}

	change := apm.StagedChange{ID: stageID, Service: service, Kind: "dotnet-otel", Impact: "restart", Command: command}
	staged, isNew, err := apm.Stage(stateDir, change, []byte(content))
	if err != nil {
		o.Facts["otelStage"] = "stage failed: " + err.Error()
		return
	}
	o.Facts["otelStage"] = staged.State
	if isNew {
		o.Events = append(o.Events, apmEvent("action_required", map[string]string{
			"service": service, "change": "dotnet-otel", "impact": "restart",
			"command": staged.Command, "stagedPath": staged.StagedPath, "host": host,
		}))
	}
}

func systemdDropin(env map[string]string, sha string) string {
	var b strings.Builder
	b.WriteString("[Service]\n")
	if sha != "" {
		fmt.Fprintf(&b, "# wakora-artifact-sha %s\n", sha)
	}
	for _, k := range dotnetEnvOrder {
		if v := env[k]; v != "" {
			fmt.Fprintf(&b, "Environment=\"%s=%s\"\n", k, v)
		}
	}
	return b.String()
}

func iisEnvScript(env map[string]string, sha string) string {
	var b strings.Builder
	b.WriteString("# Wakora APM: set $env:WAKORA_POOL to your app pool before running (defaults to DefaultAppPool)\n")
	if sha != "" {
		fmt.Fprintf(&b, "# wakora-artifact-sha %s\n", sha)
	}
	b.WriteString("$pool = $env:WAKORA_POOL; if (-not $pool) { $pool = 'DefaultAppPool' }\n")
	b.WriteString("Import-Module WebAdministration\n")
	const filter = "system.applicationHost/applicationPools/add[@name='$pool']/environmentVariables"
	for _, k := range dotnetEnvOrder {
		if v := env[k]; v != "" {
			fmt.Fprintf(&b, "Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter \"%s\" -name '.' -value @{name='%s';value='%s'}\n", filter, k, v)
		}
	}
	b.WriteString("Restart-WebAppPool $pool\n")
	return b.String()
}

var dotnetEnvOrder = []string{
	"CORECLR_ENABLE_PROFILING", "CORECLR_PROFILER", "CORECLR_PROFILER_PATH",
	"DOTNET_ADDITIONAL_DEPS", "DOTNET_SHARED_STORE", "DOTNET_STARTUP_HOOKS",
	"OTEL_DOTNET_AUTO_HOME", "OTEL_SERVICE_NAME", "OTEL_TRACES_EXPORTER",
	"OTEL_METRICS_EXPORTER", "OTEL_LOGS_EXPORTER", "OTEL_EXPORTER_OTLP_PROTOCOL",
	"OTEL_EXPORTER_OTLP_ENDPOINT",
}

func iisPoolInstrumented() (bool, bool) {
	windir := os.Getenv("windir")
	if windir == "" {
		windir = `C:\Windows`
	}
	raw, err := os.ReadFile(filepath.Join(windir, "System32", "inetsrv", "config", "applicationHost.config"))
	return err == nil && strings.Contains(string(raw), "OTEL_DOTNET_AUTO_HOME"), err == nil
}

func dotnetPlatform() (osTag, arch, nativeSub string) {
	arch = apm.Arch()
	if runtime.GOOS == "windows" {
		return "windows", arch, "win-x64"
	}
	if _, err := os.Stat("/lib/ld-musl-x86_64.so.1"); err == nil {
		return "linux-musl", arch, "linux-musl-x64"
	}
	return "linux-glibc", arch, "linux-x64"
}

func dotnetInstrumented() (loaded bool, pid int, detectOk bool) {
	if runtime.GOOS == "windows" {
		loaded, detectOk = iisPoolInstrumented()
		return loaded, 0, detectOk
	}
	if runtime.GOOS != "linux" {
		return false, 0, false
	}
	out, err := exec.Command("pgrep", "-f", "dotnet").Output()
	if err != nil {
		return false, 0, false
	}
	for _, f := range strings.Fields(string(out)) {
		p, err := strconv.Atoi(f)
		if err != nil {
			continue
		}
		environ, err := os.ReadFile("/proc/" + f + "/environ")
		if err != nil {
			continue
		}
		if apm.DotnetEnvActive(strings.ReplaceAll(string(environ), "\x00", "\n")) {
			return true, p, true
		}
	}
	return false, 0, true
}
