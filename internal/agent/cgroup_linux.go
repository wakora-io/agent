//go:build linux

package agent

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

func EnsureCgroupHeadroom() {
	unit, dir, ok := selfServiceCgroup()
	if !ok {
		return
	}
	high, haveHigh := cgroupLimit(dir, "memory.high")
	max, haveMax := cgroupLimit(dir, "memory.max")
	if !haveHigh && !haveMax {
		return
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return
	}
	args := []string{"set-property", unit}
	if haveHigh {
		args = append(args, "MemoryHigh=infinity")
	}
	if haveMax {
		args = append(args, "MemoryMax=infinity")
	}
	if out, err := exec.Command("systemctl", args...).CombinedOutput(); err != nil {
		log.Printf("cgroup headroom: %s: %v (%s)", unit, err, strings.TrimSpace(string(out)))
		return
	}
	log.Printf("cgroup memory limit lifted on %s (memory.high=%s memory.max=%s): any finite cgroup memory limit charges the page cache of everything the agent and its exec children read, and once the touched set crosses the limit every cycle re-reads from disk (heap stays capped in-process, the oom score keeps the kernel killing the agent first)",
		unit, limitLabel(high, haveHigh), limitLabel(max, haveMax))
}

func selfServiceCgroup() (string, string, bool) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", "", false
	}
	rel := ""
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "0::") {
			rel = strings.TrimPrefix(line, "0::")
			break
		}
	}
	rel = strings.TrimSpace(rel)
	if rel == "" || rel == "/" {
		return "", "", false
	}
	unit := ""
	for _, part := range strings.Split(rel, "/") {
		if strings.HasSuffix(part, ".service") {
			unit = part
		}
	}
	if unit == "" {
		return "", "", false
	}
	dir := filepath.Join("/sys/fs/cgroup", filepath.Clean(rel))
	if _, err := os.Stat(dir); err != nil {
		return "", "", false
	}
	return unit, dir, true
}

func cgroupLimit(dir, name string) (uint64, bool) {
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return 0, false
	}
	v := strings.TrimSpace(string(raw))
	if v == "" || v == "max" {
		return 0, false
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func limitLabel(v uint64, set bool) string {
	if !set {
		return "max"
	}
	return strconv.FormatUint(v/(1<<20), 10) + "M"
}
