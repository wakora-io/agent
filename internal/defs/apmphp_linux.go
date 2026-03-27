//go:build linux

package defs

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
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
	for _, v := range []string{"8.4", "8.3", "8.2", "8.1", "8.0", "7.4", "7.3", "7.2"} {
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
	for _, v := range []string{"8.4", "8.3", "8.2", "8.1", "8.0", "7.4", "7.3", "7.2"} {
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
	if p.Options["sapi"] == "apache" {
		st, errmsg := resolveApacheSAPI(p, module)
		if st == nil {
			o.Check.Status = "fail"
			o.Check.Error = errmsg
			return
		}
		runPHPTargets(o, service, p, stateDir, []*sapiTarget{st}, "apache")
		return
	}
	targets, errmsg := resolveFPMTargets(p, module)
	if len(targets) == 0 {
		o.Check.Status = "fail"
		o.Check.Error = errmsg
		return
	}
	runPHPTargets(o, service, p, stateDir, targets, "fpm")
}

func runPHPTargets(o *Outcome, service string, p protocol.Probe, stateDir string, targets []*sapiTarget, sapi string) {
	primary := targets[0]
	o.Check.Status = "ok"
	names := make([]string, 0, len(targets))
	for _, st := range targets {
		names = append(names, st.checkName)
	}
	o.Check.Target = strings.Join(names, ",")
	o.Facts = map[string]string{
		"phpVersion":   primary.rt.Version,
		"threadSafety": primary.rt.ThreadTag(),
		"arch":         primary.rt.Arch,
		"libc":         primary.rt.Libc,
		"sapi":         sapi,
		"otelArtifact": apm.OtelArtifactName(primary.rt),
	}

	prefix := "svc." + service + "."
	for _, st := range targets {
		minor := st.rt.VersionShort
		instrumented := 0.0
		if st.loaded {
			instrumented = 1
		}
		o.Metrics = append(o.Metrics, protocol.MetricPoint{
			Name: prefix + "instrumented", Value: instrumented,
			Tags: map[string]string{"php": minor},
		})
		stageID := "apmphp-" + service
		stageKey := "otelStage"
		if len(targets) > 1 {
			stageID += "-" + minor
			stageKey = "stage." + minor
			o.Facts["artifact."+minor] = apm.OtelArtifactName(st.rt)
		}
		if st.loaded {
			o.Facts[stageKey] = "active"
			if apm.StagedState(stateDir, stageID) == "pending_activation" {
				_ = apm.MarkActivated(stateDir, stageID)
				o.Events = append(o.Events, apmEvent("apm_activated", map[string]string{
					"service": service, "layer": "otel-spans", "sapi": sapi, "php": minor,
				}))
			}
			if p.Options["autostage"] == "1" && p.Options["autoprovision"] == "1" && Provision != nil {
				artifact := apm.OtelArtifactName(st.rt)
				if Provision.NeedsRefresh(artifact) {
					Provision.Ensure(artifact, false)
					o.Facts[stageKey] = "active (fetching new signed build)"
				} else if sha := Provision.LocalSha(artifact); sha != "" && sha != stagedArtifactSha(stateDir, stageID) {
					stageOtel(o, service, p, stateDir, st, stageID, stageKey)
					o.Facts[stageKey] = "active (new build staged; reload to apply)"
				}
			}
			continue
		}
		if p.Options["autostage"] != "1" {
			continue
		}
		stageOtel(o, service, p, stateDir, st, stageID, stageKey)
	}
}

func resolveFPMTargets(p protocol.Probe, module string) ([]*sapiTarget, string) {
	var bins []string
	if b := p.Options["binary"]; b != "" {
		bins = []string{b}
	} else {
		bins = runningFPMBinaries()
		if len(bins) == 0 {
			if b := phpFpmBinary(nil); b != "" {
				bins = []string{b}
			}
		}
	}
	if len(bins) == 0 {
		return nil, "php-fpm binary not found"
	}
	var targets []*sapiTarget
	var lastErr string
	for _, bin := range bins {
		st, errmsg := fpmTarget(bin, module, p.Options)
		if st == nil {
			lastErr = errmsg
			continue
		}
		targets = append(targets, st)
	}
	if len(targets) == 0 {
		return nil, lastErr
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].rt.VersionShort > targets[j].rt.VersionShort })
	return targets, ""
}

func runningFPMBinaries() []string {
	out, err := exec.Command("pgrep", "-f", "php-fpm: master").Output()
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var bins []string
	for _, f := range strings.Fields(string(out)) {
		exe, err := os.Readlink("/proc/" + f + "/exe")
		if err != nil || seen[exe] {
			continue
		}
		seen[exe] = true
		bins = append(bins, exe)
	}
	sort.Strings(bins)
	return bins
}

func fpmTarget(bin, module string, opts map[string]string) (*sapiTarget, string) {
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
		reloadCmd: reloadCommand(initSystem(), fpmUnitFor(bin, opts)),
		checkName: bin,
		preBin:    bin,
	}, ""
}

func fpmUnitFor(bin string, opts map[string]string) string {
	if s := opts["fpmService"]; s != "" {
		return s
	}
	base := filepath.Base(bin)
	if rest, ok := strings.CutPrefix(base, "php-fpm"); ok && strings.Contains(rest, ".") {
		return "php" + rest + "-fpm"
	}
	return base
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

func stageOtel(o *Outcome, service string, p protocol.Probe, stateDir string, st *sapiTarget, stageID, stageKey string) {
	if !apm.OtelSupported(st.rt.VersionShort) {
		o.Facts[stageKey] = "php " + st.rt.VersionShort + " unsupported for otel (sdk needs >= 8.1)"
		return
	}
	artifact := apm.OtelArtifactName(st.rt)
	if artifact == "" {
		o.Facts[stageKey] = "blocked: incomplete runtime fingerprint"
		return
	}
	autoprov := p.Options["autoprovision"] == "1" && Provision != nil
	soPath := filepath.Join(stateDir, "apm", artifact)
	if _, err := os.Stat(soPath); err != nil {
		if autoprov {
			o.Facts[stageKey] = Provision.Ensure(artifact, false)
		} else {
			o.Facts[stageKey] = "artifact required: " + artifact
		}
		return
	}
	if autoprov && Provision.NeedsRefresh(artifact) {
		o.Facts[stageKey] = "refreshing: " + Provision.Ensure(artifact, false)
		return
	}
	sdkDir := ""
	if p.Options["sdk"] == "1" {
		if bundle := apm.PHPSDKBundleFor(st.rt.VersionShort); bundle != "" {
			sdkDir = filepath.Join(stateDir, "apm", bundle)
			if !dirExists(sdkDir) {
				if autoprov {
					o.Facts[stageKey] = Provision.Ensure(bundle, true)
				} else {
					o.Facts[stageKey] = "artifact required: " + bundle
				}
				return
			}
			// SDK is arch-independent PHP loaded via auto_prepend_file (re-read every request),
			// so a refreshed bundle takes effect without a reload - no re-stage needed.
			if autoprov && Provision.NeedsRefresh(bundle) {
				_ = Provision.Ensure(bundle, true)
			}
		}
	}
	if err := preflightExtension(st.preBin, soPath); err != nil {
		o.Facts[stageKey] = "preflight failed: " + err.Error()
		return
	}
	if sdkDir != "" {
		if err := preflightPrepend(soPath, sdkDir+"/wakora-otel.php"); err != nil {
			o.Facts[stageKey] = "sdk preflight failed: " + err.Error()
			return
		}
	}
	target := filepath.Join(st.iniDir, "90-wakora-otel.ini")
	endpoint := p.Options["otelEndpoint"]
	if endpoint == "" {
		endpoint = "http://127.0.0.1:4318"
	}
	artifactSha := ""
	if autoprov {
		artifactSha = Provision.LocalSha(artifact)
	}
	ini := apm.OtelIni(soPath, service, endpoint, sdkDir, artifactSha)
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
		o.Facts[stageKey] = "stage failed: " + err.Error()
		return
	}
	o.Facts[stageKey] = staged.State
	if isNew {
		o.Events = append(o.Events, apmEvent("action_required", map[string]string{
			"service": service, "change": "otel-spans", "impact": "reload",
			"command": staged.Command, "stagedPath": staged.StagedPath, "target": target,
			"php": st.rt.VersionShort,
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

func preflightPrepend(soPath, prependPath string) error {
	if err := worldAccessible(prependPath); err != nil {
		return err
	}
	cli := phpCLIBinary()
	if cli == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, cli,
		"-d", "extension="+soPath,
		"-d", "auto_prepend_file="+prependPath,
		"-r", ";").Run()
}

func worldAccessible(path string) error {
	cur := string(os.PathSeparator)
	for _, part := range strings.Split(filepath.Clean(path), string(os.PathSeparator)) {
		if part == "" {
			continue
		}
		cur = filepath.Join(cur, part)
		fi, err := os.Stat(cur)
		if err != nil {
			return err
		}
		if fi.IsDir() {
			if fi.Mode().Perm()&0o005 != 0o005 {
				return fmt.Errorf("%s mode %o blocks php workers (needs o+rx)", cur, fi.Mode().Perm())
			}
		} else if fi.Mode().Perm()&0o004 == 0 {
			return fmt.Errorf("%s mode %o blocks php workers (needs o+r)", cur, fi.Mode().Perm())
		}
	}
	return nil
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
