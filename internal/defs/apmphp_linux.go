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
	for _, c := range []string{"php-fpm8.4", "php-fpm8.3", "php-fpm8.2", "php-fpm8.1", "php-fpm8.0", "php-fpm7.4", "php-fpm"} {
		if path, err := exec.LookPath(c); err == nil {
			return path
		}
	}
	return ""
}

func runAPMPhp(o *Outcome, service string, p protocol.Probe, dir string) {
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
		if apm.StagedState(dir, stageID) == "pending_activation" {
			_ = apm.MarkActivated(dir, stageID)
			o.Events = append(o.Events, apmEvent("apm_activated", map[string]string{"service": service, "layer": "otel-spans"}))
		}
		return
	}
	if p.Options["autostage"] != "1" {
		return
	}
	stageOtel(o, service, p, dir, rt, stageID)
}

func stageOtel(o *Outcome, service string, p protocol.Probe, dir string, rt apm.PHPRuntime, stageID string) {
	artifact := apm.OtelArtifactName(rt)
	if artifact == "" {
		o.Facts["otelStage"] = "blocked: incomplete runtime fingerprint"
		return
	}
	soPath := filepath.Join(dir, "apm", artifact)
	if _, err := os.Stat(soPath); err != nil {
		o.Facts["otelStage"] = "artifact required: " + artifact
		return
	}
	if err := preflightExtension(p.Options["binary"], soPath); err != nil {
		o.Facts["otelStage"] = "preflight failed: " + err.Error()
		return
	}
	endpoint := p.Options["otelEndpoint"]
	if endpoint == "" {
		endpoint = "http://127.0.0.1:4318"
	}
	target := p.Options["iniTarget"]
	if target == "" {
		target = "/etc/php/conf.d/90-wakora-otel.ini"
	}
	ini := apm.OtelIni(soPath, service, endpoint)
	change := apm.StagedChange{
		ID:         stageID,
		Service:    service,
		Kind:       "otel-spans",
		TargetPath: target,
		Impact:     "reload",
	}
	change.Command = "cp " + filepath.Join(dir, "staged", stageID+".staged") + " " + target + " && systemctl reload php-fpm"
	staged, isNew, err := apm.Stage(dir, change, []byte(ini))
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
