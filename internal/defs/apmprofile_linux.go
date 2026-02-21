//go:build linux

package defs

import (
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"wakora.io/agent/internal/apm"
	"wakora.io/agent/internal/protocol"
)

const (
	profileDefaultHz     = 200
	profileDefaultWindow = 10
	profileMaxStacks     = 200
)

func runAPMProfile(o *Outcome, service string, p protocol.Probe) {
	if ok, reason := apm.ProfileSupported(); !ok {
		o.Check.Status = "fail"
		o.Check.Error = reason
		return
	}
	pids := phpFpmWorkers(p.Options["process"])
	if len(pids) == 0 {
		o.Check.Status = "fail"
		o.Check.Error = "no php-fpm worker processes found"
		return
	}
	version := p.Options["phpVersion"]
	if version == "" {
		version = detectPHPMinor(pids[0])
	}
	if version == "" {
		o.Check.Status = "fail"
		o.Check.Error = "could not determine php version (set options.phpVersion)"
		return
	}
	var samplers []*apm.PHPSampler
	for _, pid := range pids {
		s, err := apm.NewPHPSampler(pid, version)
		if err != nil {
			continue
		}
		samplers = append(samplers, s)
	}
	if len(samplers) == 0 {
		o.Check.Status = "fail"
		o.Check.Error = "no attachable php-fpm workers (php " + version + " offsets or symbol)"
		return
	}

	hz := p.Options["hz"]
	rate, _ := strconv.Atoi(hz)
	if rate <= 0 || rate > 1000 {
		rate = profileDefaultHz
	}
	windowSec := p.TimeoutSec
	if windowSec <= 0 || windowSec > 30 {
		windowSec = profileDefaultWindow
	}

	folded := map[string]uint32{}
	var total, hits uint32
	interval := time.Second / time.Duration(rate)
	deadline := time.Now().Add(time.Duration(windowSec) * time.Second)
	for time.Now().Before(deadline) {
		for _, s := range samplers {
			total++
			frames, err := s.Sample()
			if err != nil || len(frames) == 0 {
				continue
			}
			hits++
			folded[strings.Join(frames, ";")]++
		}
		time.Sleep(interval)
	}

	o.Check.Status = "ok"
	o.Check.Target = "process_vm_readv php-fpm x" + strconv.Itoa(len(samplers))
	o.ProfileStacks = topStacks(folded, profileMaxStacks)
	o.ProfileMeta = protocol.ProfileBatch{
		Service: service, WindowSec: uint32(windowSec), SampleRate: uint32(rate),
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

func detectPHPMinor(pid int) string {
	exe, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil {
		return ""
	}
	out, err := exec.Command(exe, "-n", "-v").Output()
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(out))
	if len(fields) < 2 {
		return ""
	}
	return apm.MinorVersion(fields[1])
}

func phpFpmWorkers(pattern string) []int {
	if pattern == "" {
		pattern = "php-fpm: pool"
	}
	out, err := exec.Command("pgrep", "-f", pattern).Output()
	if err != nil {
		return nil
	}
	var pids []int
	for _, line := range strings.Fields(string(out)) {
		if pid, err := strconv.Atoi(line); err == nil && pid != os.Getpid() {
			pids = append(pids, pid)
		}
	}
	return pids
}

func topStacks(folded map[string]uint32, max int) []protocol.FoldedStack {
	stacks := make([]protocol.FoldedStack, 0, len(folded))
	for k, v := range folded {
		stacks = append(stacks, protocol.FoldedStack{Stack: k, Samples: v})
	}
	sort.Slice(stacks, func(i, j int) bool { return stacks[i].Samples > stacks[j].Samples })
	if len(stacks) > max {
		stacks = stacks[:max]
	}
	return stacks
}
