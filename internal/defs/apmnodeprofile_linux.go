//go:build linux

package defs

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"wakora.io/agent/internal/protocol"
)

const (
	nodeProfileWindow    = 10
	nodeProfileHz        = 99
	nodeProfileMaxStacks = 200
	nodeProfileMaxProcs  = 12
)

var perfOffsetRe = regexp.MustCompile(`\+0x[0-9a-f]+$`)

func runAPMNodeProfile(o *Outcome, service string, p protocol.Probe) {
	if !nodeProfileAllowed.Load() && p.Options["profile"] != "1" {
		o.Check.Status = "ok"
		o.Check.Target = "cpu profiler not enabled for this host"
		return
	}
	if os.Geteuid() != 0 {
		o.Check.Status = "fail"
		o.Check.Error = "node cpu profiling needs root (perf CAP_PERFMON)"
		return
	}
	if _, err := exec.LookPath("perf"); err != nil {
		o.Check.Status = "fail"
		o.Check.Error = "perf not installed"
		return
	}
	proc := p.Process
	if proc == "" {
		proc = "node"
	}
	var pids []int
	mapped := 0
	for _, m := range nodeMasters(proc) {
		pids = append(pids, m.pid)
		if _, err := os.Stat("/tmp/perf-" + strconv.Itoa(m.pid) + ".map"); err == nil {
			mapped++
		}
		if len(pids) >= nodeProfileMaxProcs {
			break
		}
	}
	if len(pids) == 0 {
		o.Check.Status = "fail"
		o.Check.Error = "no node processes outside containers"
		return
	}
	if mapped == 0 {
		o.Check.Status = "fail"
		o.Check.Error = "node started without --perf-basic-prof - enable the cpu profiler grant so js frames resolve"
		return
	}
	windowSec := p.TimeoutSec
	if windowSec <= 0 || windowSec > 30 {
		windowSec = nodeProfileWindow
	}
	data := filepath.Join(os.TempDir(), "wk-nodeperf-"+strconv.Itoa(pids[0])+".data")
	defer os.Remove(data)
	pidList := make([]string, len(pids))
	for i, pid := range pids {
		pidList[i] = strconv.Itoa(pid)
	}
	args := []string{"record", "-F", strconv.Itoa(nodeProfileHz), "-g", "-o", data, "-p", strings.Join(pidList, ","), "--", "sleep", strconv.Itoa(windowSec)}
	if err := exec.Command("perf", args...).Run(); err != nil {
		o.Check.Status = "fail"
		o.Check.Error = "perf record: " + err.Error()
		return
	}
	out, err := exec.Command("perf", "script", "-i", data).Output()
	if err != nil {
		o.Check.Status = "fail"
		o.Check.Error = "perf script: " + err.Error()
		return
	}
	folded, total, hits := foldPerfScript(string(out))
	o.Check.Status = "ok"
	o.Check.Target = "perf record node x" + strconv.Itoa(len(pids))
	o.ProfileStacks = topStacks(folded, nodeProfileMaxStacks)
	o.ProfileMeta = protocol.ProfileBatch{
		Service: service, WindowSec: uint32(windowSec), SampleRate: uint32(nodeProfileHz),
		SampleTotal: total, SampleHits: hits,
	}
	prefix := "svc." + service + "."
	busy := 0.0
	if total > 0 {
		busy = float64(hits) / float64(total) * 100
	}
	o.Metrics = append(o.Metrics,
		protocol.MetricPoint{Name: prefix + "busy_pct", Value: float64(int(busy*10+0.5)) / 10},
		protocol.MetricPoint{Name: prefix + "unique_stacks", Value: float64(len(folded))},
	)
}

func foldPerfScript(out string) (map[string]uint32, uint32, uint32) {
	folded := map[string]uint32{}
	var total, hits uint32
	for _, block := range strings.Split(out, "\n\n") {
		lines := strings.Split(strings.TrimRight(block, "\n"), "\n")
		if len(lines) < 2 {
			continue
		}
		total++
		var frames []string
		for _, ln := range lines[1:] {
			sym := perfFrameSymbol(ln)
			if sym == "" {
				continue
			}
			frames = append(frames, sym)
		}
		if len(frames) == 0 {
			continue
		}
		for i, j := 0, len(frames)-1; i < j; i, j = i+1, j-1 {
			frames[i], frames[j] = frames[j], frames[i]
		}
		if len(frames) > 64 {
			frames = frames[len(frames)-64:]
		}
		hits++
		folded[strings.Join(frames, ";")]++
	}
	return folded, total, hits
}

func perfFrameSymbol(line string) string {
	s := strings.TrimSpace(line)
	if s == "" {
		return ""
	}
	sp := strings.IndexByte(s, ' ')
	if sp < 0 {
		return ""
	}
	s = strings.TrimSpace(s[sp+1:])
	if i := strings.LastIndex(s, " ("); i >= 0 {
		s = s[:i]
	}
	if s == "" || strings.HasPrefix(s, "[unknown]") {
		return ""
	}
	s = perfOffsetRe.ReplaceAllString(s, "")
	s = strings.TrimPrefix(s, "Function:* ")
	s = strings.TrimPrefix(s, "Function:^ ")
	if len(s) > 160 {
		s = s[:160]
	}
	return s
}
