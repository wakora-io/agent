//go:build linux

package defs

import (
	"context"
	"math/rand"
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
	profileMaxWorkers    = 24
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

	rand.Shuffle(len(pids), func(i, j int) { pids[i], pids[j] = pids[j], pids[i] })
	forced := p.Options["phpVersion"]
	verByExe := map[string]string{}
	var samplers []*apm.PHPSampler
	var pools []string
	seen := map[string]bool{}
	for _, pid := range pids {

		if len(samplers) >= profileMaxWorkers {
			break
		}
		version := forced
		if version == "" {
			exe, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
			if err != nil {
				continue
			}
			v, ok := verByExe[exe]
			if !ok {
				v = detectPHPMinorExe(exe)
				verByExe[exe] = v
			}
			version = v
		}
		if version == "" {
			continue
		}
		seen[version] = true
		s, err := apm.NewPHPSampler(pid, version)
		if err != nil {
			continue
		}
		samplers = append(samplers, s)
		pools = append(pools, poolOfPid(pid))
	}
	if len(samplers) == 0 {
		versions := make([]string, 0, len(seen))
		for v := range seen {
			versions = append(versions, v)
		}
		sort.Strings(versions)
		o.Check.Status = "fail"
		o.Check.Error = "no attachable php-fpm workers (php " + strings.Join(versions, ",") + " offsets or symbol)"
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
	owners := map[string]uint32{}
	var total, hits uint32

	interval := time.Second / time.Duration(rate)
	deadline := time.Now().Add(time.Duration(windowSec) * time.Second)
	cursor := 0
	for time.Now().Before(deadline) {
		i := cursor % len(samplers)
		s := samplers[i]
		cursor++
		total++
		frames, owner, err := s.Sample()
		if err == nil && len(frames) > 0 {
			hits++
			folded[pools[i]+"\x1f"+strings.Join(frames, ";")]++
			if owner != "" {
				owners[owner]++
			}
		}
		time.Sleep(interval)
	}

	o.Check.Status = "ok"
	o.Check.Target = "process_vm_readv php-fpm x" + strconv.Itoa(len(samplers))
	stacks := topStacks(folded, profileMaxStacks)
	for i := range stacks {
		if j := strings.Index(stacks[i].Stack, "\x1f"); j >= 0 {
			stacks[i].Pool = stacks[i].Stack[:j]
			stacks[i].Stack = stacks[i].Stack[j+1:]
		}
	}
	o.ProfileStacks = stacks
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
	if hits > 0 {
		for _, ow := range topOwners(owners, 15) {
			pct := float64(owners[ow]) / float64(hits) * 100
			o.Metrics = append(o.Metrics,
				protocol.MetricPoint{
					Name:  prefix + "owner_pct",
					Value: float64(int(pct*10+0.5)) / 10,
					Tags:  map[string]string{"owner": ow},
				},

				protocol.MetricPoint{
					Name:  prefix + "owner_samples",
					Value: float64(owners[ow]),
					Tags:  map[string]string{"owner": ow},
				},
			)
		}
	}
}

func topOwners(owners map[string]uint32, max int) []string {
	keys := make([]string, 0, len(owners))
	for k := range owners {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return owners[keys[i]] > owners[keys[j]] })
	if len(keys) > max {
		keys = keys[:max]
	}
	return keys
}

func detectPHPMinorExe(exe string) string {
	exe = strings.TrimSuffix(strings.TrimSpace(exe), " (deleted)")
	if exe == "" || !strings.HasPrefix(exe, "/") {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	out, err := trustedOutput(ctx, exe, "-n", "-v")
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(out))
	if len(fields) < 2 {
		return ""
	}
	return apm.MinorVersion(fields[1])
}

func poolOfPid(pid int) string {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil {
		return ""
	}
	s := strings.ReplaceAll(string(data), "\x00", " ")
	if i := strings.Index(s, "pool "); i >= 0 {
		return strings.TrimSpace(s[i+5:])
	}
	return ""
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
