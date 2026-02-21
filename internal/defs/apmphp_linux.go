//go:build linux

package defs

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"wakora.io/agent/internal/apm"
	"wakora.io/agent/internal/protocol"
)

type sapiTarget struct {
	rt        apm.PHPRuntime
	loaded    bool
	iniDir    string
	reloadCmd string
	checkName string
	preBin    string
}

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

func phpCLIBinary() string {
	candidates := []string{"php"}
	for _, v := range []string{"8.4", "8.3", "8.2", "8.1", "8.0", "7.4"} {
		candidates = append(candidates, "php"+v)
	}
	for _, c := range candidates {
		if path, err := exec.LookPath(c); err == nil {
			return path
		}
	}
	return ""
}

func runAPMPhp(o *Outcome, service string, p protocol.Probe, stateDir string) {
	module := p.Options["module"]
	if module == "" {
		module = "opentelemetry"
	}
	var st *sapiTarget
	var errmsg string
	if p.Options["sapi"] == "apache" {
		st, errmsg = resolveApacheSAPI(p, module)
	} else {
		st, errmsg = resolveFPMSAPI(p, module)
	}
	if st == nil {
		o.Check.Status = "fail"
		o.Check.Error = errmsg
		return
	}

	o.Check.Status = "ok"
	o.Check.Target = st.checkName
	prefix := "svc." + service + "."
	instrumented := 0.0
	if st.loaded {
		instrumented = 1
	}
	o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: prefix + "instrumented", Value: instrumented})
	sapi := p.Options["sapi"]
	if sapi == "" {
		sapi = "fpm"
	}
	o.Facts = map[string]string{
		"phpVersion":   st.rt.Version,
		"threadSafety": st.rt.ThreadTag(),
		"arch":         st.rt.Arch,
		"libc":         st.rt.Libc,
		"sapi":         sapi,
		"otelArtifact": apm.OtelArtifactName(st.rt),
	}

	stageID := "apmphp-" + service
	if st.loaded {
		o.Facts["otelStage"] = "active"
		if apm.StagedState(stateDir, stageID) == "pending_activation" {
			_ = apm.MarkActivated(stateDir, stageID)
			o.Events = append(o.Events, apmEvent("apm_activated", map[string]string{"service": service, "layer": "otel-spans", "sapi": sapi}))
		}
		return
	}
	if p.Options["autostage"] != "1" {
		return
	}
	stageOtel(o, service, p, stateDir, st, stageID)
}

func resolveFPMSAPI(p protocol.Probe, module string) (*sapiTarget, string) {
	bin := phpFpmBinary(p.Options)
	if bin == "" {
		return nil, "php-fpm binary not found"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	info, err := exec.CommandContext(ctx, bin, "-i").Output()
	if err != nil {
		return nil, "php-fpm -i: " + err.Error()
	}
	rt := apm.ParsePHPInfo(string(info))
	rt.Arch = apm.Arch()
	rt.Libc = detectLibc(bin)
	modules, _ := exec.CommandContext(ctx, bin, "-m").Output()
	return &sapiTarget{
		rt:        rt,
		loaded:    apm.ModuleLoaded(string(modules), module),
		iniDir:    rt.ScanDir,
		reloadCmd: reloadCommand(initSystem(), fpmServiceName(p.Options)),
		checkName: bin,
		preBin:    bin,
	}, ""
}

func resolveApacheSAPI(p protocol.Probe, module string) (*sapiTarget, string) {
	bin := phpCLIBinary()
	if bin == "" {
		return nil, "php cli binary not found (needed to fingerprint mod_php)"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	info, err := exec.CommandContext(ctx, bin, "-i").Output()
	if err != nil {
		return nil, "php -i: " + err.Error()
	}
	rt := apm.ParsePHPInfo(string(info))
	rt.Arch = apm.Arch()
	rt.Libc = detectLibc(bin)

	iniDir := p.Options["iniTarget"]
	if iniDir == "" {
		iniDir = apacheConfd(rt.VersionShort)
	}
	if iniDir == "" {
		return nil, "mod_php conf.d not found (set options.iniTarget)"
	}

	loaded := false
	scan := exec.CommandContext(ctx, bin, "-m")
	scan.Env = append(os.Environ(), "PHP_INI_SCAN_DIR="+iniDir)
	if out, err := scan.Output(); err == nil {
		loaded = apm.ModuleLoaded(string(out), module)
	}

	svc := apacheServiceName(p.Options)
	return &sapiTarget{
		rt:        rt,
		loaded:    loaded,
		iniDir:    iniDir,
		reloadCmd: reloadCommand(initSystem(), svc),
		checkName: "mod_php (" + svc + ")",
		preBin:    bin,
	}, ""
}

func apacheConfd(versionShort string) string {
	if versionShort != "" {
		if d := "/etc/php/" + versionShort + "/apache2/conf.d"; dirExists(d) {
			return d
		}
	}
	if dirExists("/etc/php.d") {
		return "/etc/php.d"
	}
	return ""
}

func apacheServiceName(opts map[string]string) string {
	if s := opts["apacheService"]; s != "" {
		return s
	}
	if fileExists("/usr/sbin/httpd") || fileExists("/etc/httpd") {
		return "httpd"
	}
	return "apache2"
}

func fpmServiceName(opts map[string]string) string {
	if s := opts["fpmService"]; s != "" {
		return s
	}
	return "php-fpm"
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func stageOtel(o *Outcome, service string, p protocol.Probe, stateDir string, st *sapiTarget, stageID string) {
	artifact := apm.OtelArtifactName(st.rt)
	if artifact == "" {
		o.Facts["otelStage"] = "blocked: incomplete runtime fingerprint"
		return
	}
	soPath := filepath.Join(stateDir, "apm", artifact)
	if _, err := os.Stat(soPath); err != nil {
		o.Facts["otelStage"] = "artifact required: " + artifact
		return
	}
	if err := preflightExtension(st.preBin, soPath); err != nil {
		o.Facts["otelStage"] = "preflight failed: " + err.Error()
		return
	}
	target := filepath.Join(st.iniDir, "90-wakora-otel.ini")
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
		Command:    "cp " + stagedPath + " " + target + " && " + st.reloadCmd,
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

func reloadCommand(init, svc string) string {
	switch init {
	case "openrc":
		return "rc-service " + svc + " reload"
	case "sysvinit":
		return "service " + svc + " reload"
	default:
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

func preflightExtension(bin, soPath string) error {
	if bin == "" {
		bin = phpFpmBinary(nil)
	}
	if bin == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, bin, "-d", "extension="+soPath, "-v").Run()
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
