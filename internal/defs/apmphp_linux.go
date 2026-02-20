//go:build linux

package defs

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"wakora.io/agent/internal/apm"
	"wakora.io/agent/internal/protocol"
)

func phpFpmBinary(opts map[string]string) string {
	if opts["binary"] != "" {
		return opts["binary"]
	}
	candidates := []string{"php-fpm"}
	for _, v := range []string{"8.4", "8.3", "8.2", "8.1", "8.0", "7.4"} {
		short := strings.ReplaceAll(v, ".", "")
		candidates = append(candidates, "php-fpm"+v, "php-fpm"+short, "php"+short+"-php-fpm")
	}
	for _, c := range candidates {
		if path, err := exec.LookPath(c); err == nil {
			return path
		}
	}
	return ""
}

func runAPMPhp(o *Outcome, service string, p protocol.Probe, stateDir string) {
	bin := phpFpmBinary(p.Options)
	if bin == "" {
		o.Check.Status = "fail"
		o.Check.Error = "php-fpm binary not found"
		return
	}
	o.Check.Target = bin
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	info, err := exec.CommandContext(ctx, bin, "-i").Output()
	if err != nil {
		o.Check.Status = "fail"
		o.Check.Error = "php-fpm -i: " + err.Error()
		return
	}
	rt := apm.ParsePHPInfo(string(info))
	rt.Arch = apm.Arch()
	rt.Libc = detectLibc(bin)

	module := p.Options["module"]
	if module == "" {
		module = "opentelemetry"
	}
	modules, _ := exec.CommandContext(ctx, bin, "-m").Output()
	loaded := apm.ModuleLoaded(string(modules), module)

	o.Check.Status = "ok"
	prefix := "svc." + service + "."
	instrumented := 0.0
	if loaded {
		instrumented = 1
	}
	o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: prefix + "instrumented", Value: instrumented})
	o.Facts = map[string]string{
		"phpVersion":   rt.Version,
		"threadSafety": rt.ThreadTag(),
		"arch":         rt.Arch,
		"libc":         rt.Libc,
		"otelArtifact": apm.OtelArtifactName(rt),
	}

	stageID := "apmphp-" + service
	if loaded {
		o.Facts["otelStage"] = "active"
		if apm.StagedState(stateDir, stageID) == "pending_activation" {
			_ = apm.MarkActivated(stateDir, stageID)
			o.Events = append(o.Events, apmEvent("apm_activated", map[string]string{"service": service, "layer": "otel-spans"}))
		}
		return
	}
	if p.Options["autostage"] != "1" {
		return
	}
	stageOtel(o, service, p, stateDir, rt, stageID)
}

func stageOtel(o *Outcome, service string, p protocol.Probe, stateDir string, rt apm.PHPRuntime, stageID string) {
	artifact := apm.OtelArtifactName(rt)
	if artifact == "" {
		o.Facts["otelStage"] = "blocked: incomplete runtime fingerprint"
		return
	}
	soPath := filepath.Join(stateDir, "apm", artifact)
	if _, err := os.Stat(soPath); err != nil {
		o.Facts["otelStage"] = "artifact required: " + artifact
		return
	}
	if err := preflightExtension(p.Options["binary"], soPath); err != nil {
		o.Facts["otelStage"] = "preflight failed: " + err.Error()
		return
	}
	target := p.Options["iniTarget"]
	if target == "" {
		if rt.ScanDir == "" {
			o.Facts["otelStage"] = "blocked: no php conf.d scan dir (set options.iniTarget)"
			return
		}
		target = filepath.Join(rt.ScanDir, "90-wakora-otel.ini")
	}
	endpoint := p.Options["otelEndpoint"]
	if endpoint == "" {
		endpoint = "http://127.0.0.1:4318"
	}
	ini := apm.OtelIni(soPath, service, endpoint)
	stagedPath := filepath.Join(stateDir, "staged", stageID+".staged")
	change := apm.StagedChange{
		ID:         stageID,
		Service:    service,
		Kind:       "otel-spans",
		TargetPath: target,
		Impact:     "reload",
		Command:    "cp " + stagedPath + " " + target + " && " + reloadCommand(p.Options),
	}
	staged, isNew, err := apm.Stage(stateDir, change, []byte(ini))
	if err != nil {
		o.Facts["otelStage"] = "stage failed: " + err.Error()
		return
	}
	o.Facts["otelStage"] = staged.State
	if isNew {
		o.Events = append(o.Events, apmEvent("action_required", map[string]string{
			"service": service, "change": "otel-spans", "impact": "reload",
			"command": staged.Command, "stagedPath": staged.StagedPath, "target": target,
		}))
	}
}

func reloadCommand(opts map[string]string) string {
	svc := opts["fpmService"]
	switch initSystem() {
	case "openrc":
		if svc == "" {
			svc = "php-fpm"
		}
		return "rc-service " + svc + " reload"
	case "sysvinit":
		if svc == "" {
			svc = "php-fpm"
		}
		return "service " + svc + " reload"
	default:
		if svc == "" {
			svc = "php-fpm"
		}
		return "systemctl reload " + svc
	}
}

func initSystem() string {
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		return "systemd"
	}
	if _, err := os.Stat("/run/openrc"); err == nil {
		return "openrc"
	}
	if _, err := os.Stat("/etc/inittab"); err == nil {
		return "sysvinit"
	}
	return "systemd"
}

func apmEvent(kind string, detail map[string]string) protocol.AgentEvent {
	raw, _ := json.Marshal(detail)
	return protocol.AgentEvent{Kind: kind, Detail: string(raw)}
}

func preflightExtension(bin, soPath string) error {
	if bin == "" {
		bin = phpFpmBinary(nil)
	}
	if bin == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, bin, "-d", "zend_extension="+soPath, "-v").Run()
}

func detectLibc(bin string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ldd", bin).Output()
	if err == nil && strings.Contains(string(out), "musl") {
		return "musl"
	}
	if _, e := os.Stat("/lib/ld-musl-x86_64.so.1"); e == nil {
		return "musl"
	}
	return "glibc"
}
