package defs

import (
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

const (
	dotnetProfileWindow    = 10
	dotnetProfileMaxStacks = 200
)

// RunAPMDotnetProfile captures a CPU flamegraph of a running .NET process via the
// provisioned dotnet-trace tool (EventPipe SampleProfiler): collect a short window
// into a nettrace, convert to speedscope, fold stacks by self-time.
func RunAPMDotnetProfile(service string, p protocol.Probe, stateDir string) Outcome {
	o := Outcome{Check: protocol.CheckResult{
		CheckID:   service + "/" + p.Name,
		Kind:      p.Type,
		Timestamp: time.Now().Unix(),
	}}
	start := time.Now()
	runAPMDotnetProfile(&o, service, p, stateDir)
	o.Check.LatencyMs = float64(time.Since(start).Microseconds()) / 1000
	return o
}

func runAPMDotnetProfile(o *Outcome, service string, p protocol.Probe, stateDir string) {
	osTag, arch, _ := dotnetPlatform()
	tool := apm.DotnetTraceName(osTag, arch)
	toolPath := filepath.Join(stateDir, "apm", tool)
	if _, err := os.Stat(toolPath); err != nil {
		if p.Options["autoprovision"] == "1" && Provision != nil {
			o.Check.Status = "ok"
			o.Facts = map[string]string{"profileStage": Provision.Ensure(tool, false)}
			return
		}
		o.Check.Status = "fail"
		o.Check.Error = "artifact required: " + tool + " (dotnet-trace single-file)"
		return
	}
	_ = os.Chmod(toolPath, 0o755)

	pid := dotnetTargetPid(toolPath, p.Options["process"])
	if pid <= 0 {
		o.Check.Status = "fail"
		o.Check.Error = "no .NET process with an open EventPipe diagnostic channel found"
		return
	}

	windowSec := p.TimeoutSec
	if windowSec <= 0 || windowSec > 30 {
		windowSec = dotnetProfileWindow
	}

	tmpDir, err := os.MkdirTemp("", "wakora-dotnet-prof")
	if err != nil {
		o.Check.Status = "fail"
		o.Check.Error = err.Error()
		return
	}
	defer os.RemoveAll(tmpDir)
	traceFile := filepath.Join(tmpDir, "cpu.nettrace")

	// explicit provider instead of --profile cpu-sampling: profile names changed
	// across dotnet-trace releases (2026 builds reject the old name)
	collect := exec.Command(toolPath, "collect",
		"--process-id", strconv.Itoa(pid),
		"--providers", "Microsoft-DotNETCore-SampleProfiler",
		"--duration", "00:00:00:"+twoDigits(windowSec),
		"--output", traceFile)
	collect.Env = dotnetToolEnv(tmpDir)
	if out, err := collect.CombinedOutput(); err != nil {
		o.Check.Status = "fail"
		o.Check.Error = "dotnet-trace collect: " + firstLine(string(out), err)
		return
	}

	convert := exec.Command(toolPath, "convert", traceFile, "--format", "Speedscope")
	convert.Env = dotnetToolEnv(tmpDir)
	if out, err := convert.CombinedOutput(); err != nil {
		o.Check.Status = "fail"
		o.Check.Error = "dotnet-trace convert: " + firstLine(string(out), err)
		return
	}
	data, err := os.ReadFile(filepath.Join(tmpDir, "cpu.speedscope.json"))
	if err != nil {
		o.Check.Status = "fail"
		o.Check.Error = "speedscope output missing: " + err.Error()
		return
	}
	folded, totalMs, err := apm.FoldSpeedscope(data)
	if err != nil {
		o.Check.Status = "fail"
		o.Check.Error = "speedscope parse: " + err.Error()
		return
	}

	o.Check.Status = "ok"
	o.Check.Target = "eventpipe pid " + strconv.Itoa(pid)
	o.ProfileStacks = topStacks(folded, dotnetProfileMaxStacks)
	o.ProfileMeta = protocol.ProfileBatch{
		Service: service, WindowSec: uint32(windowSec), SampleRate: 0,
		SampleTotal: uint32(totalMs + 0.5), SampleHits: uint32(len(folded)),
	}
	prefix := "svc." + service + "."
	busy := 0.0
	if windowSec > 0 {
		busy = totalMs / float64(windowSec*1000) * 100
		if busy > 100 {
			busy = 100
		}
	}
	o.Metrics = append(o.Metrics,
		protocol.MetricPoint{Name: prefix + "busy_pct", Value: float64(int(busy*10+0.5)) / 10},
		protocol.MetricPoint{Name: prefix + "unique_stacks", Value: float64(len(folded))},
	)
	o.Facts = map[string]string{"profileStage": "active", "pid": strconv.Itoa(pid)}
}

func dotnetTargetPid(toolPath, pattern string) int {
	out, err := exec.Command(toolPath, "ps").Output()
	if err != nil {
		return 0
	}
	pids := apm.ParseDotnetTracePS(string(out), pattern)
	self := os.Getpid()
	for _, pid := range pids {
		if pid != self {
			return pid
		}
	}
	return 0
}

// dotnet-trace is a self-contained .NET tool: point runtime scratch paths at the
// temp dir so it never writes under the agent's own HOME/state. TMPDIR must stay
// untouched on linux - the EventPipe diagnostic sockets it discovers live in /tmp.
func dotnetToolEnv(tmpDir string) []string {
	env := append(os.Environ(),
		"DOTNET_CLI_TELEMETRY_OPTOUT=1",
		"DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1",
		"DOTNET_BUNDLE_EXTRACT_BASE_DIR="+filepath.Join(tmpDir, "bundle"),
	)
	if runtime.GOOS == "windows" {
		env = append(env, "TEMP="+tmpDir, "TMP="+tmpDir)
	} else {
		env = append(env, "HOME="+tmpDir)
	}
	return env
}

func twoDigits(n int) string {
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

func firstLine(out string, err error) string {
	out = strings.TrimSpace(out)
	if out == "" {
		return err.Error()
	}
	lines := strings.Split(out, "\n")
	last := strings.TrimSpace(lines[len(lines)-1])
	if len(last) > 300 {
		last = last[:300]
	}
	return last
}
