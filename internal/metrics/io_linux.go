//go:build linux

package metrics

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type ioState struct {
	at          time.Time
	psi         uint64
	hasPSI      bool
	read        uint64
	write       uint64
	hasBytes    bool
	ticks       map[string]uint64
	inContainer bool
}

func (c *Collector) ioPoints(now time.Time) []Point {
	prev := c.io
	cur := ioState{at: now, inContainer: inContainer("/")}
	if cur.inContainer {
		if b, err := os.ReadFile("/sys/fs/cgroup/io.pressure"); err == nil {
			cur.psi, cur.hasPSI = parsePSITotal(string(b))
		}
		if b, err := os.ReadFile("/sys/fs/cgroup/io.stat"); err == nil {
			cur.read, cur.write, cur.hasBytes = parseIOStat(string(b), blockDevicePhysical)
		}
	} else {
		if b, err := os.ReadFile("/proc/pressure/io"); err == nil {
			cur.psi, cur.hasPSI = parsePSITotal(string(b))
		}
		if b, err := os.ReadFile("/proc/diskstats"); err == nil {
			cur.read, cur.write, cur.ticks = parseDiskstats(string(b), blockNamePhysical)
			cur.hasBytes = cur.ticks != nil
		}
	}
	c.io = cur
	if prev.at.IsZero() || prev.inContainer != cur.inContainer {
		return nil
	}
	elapsed := now.Sub(prev.at)
	if elapsed <= 0 {
		return nil
	}
	var pts []Point
	if cur.hasPSI && prev.hasPSI && cur.psi >= prev.psi {
		pct := float64(cur.psi-prev.psi) / float64(elapsed.Microseconds()) * 100
		pts = append(pts, Point{Name: "host.io.pressure_pct", Value: clampPct(pct)})
	}
	if cur.hasBytes && prev.hasBytes && cur.read >= prev.read && cur.write >= prev.write {
		sec := elapsed.Seconds()
		pts = append(pts,
			Point{Name: "host.io.read_bytes_per_sec", Value: float64(cur.read-prev.read) / sec},
			Point{Name: "host.io.write_bytes_per_sec", Value: float64(cur.write-prev.write) / sec},
		)
	}
	if busy, ok := diskBusyPct(prev.ticks, cur.ticks, elapsed); ok {
		pts = append(pts, Point{Name: "host.io.busy_pct", Value: busy})
	}
	return pts
}

func clampPct(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func parsePSITotal(s string) (uint64, bool) {
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] != "some" {
			continue
		}
		for _, kv := range f[1:] {
			if v, ok := strings.CutPrefix(kv, "total="); ok {
				n, err := strconv.ParseUint(v, 10, 64)
				return n, err == nil
			}
		}
	}
	return 0, false
}

func parseDiskstats(s string, physical func(string) bool) (read, write uint64, ticks map[string]uint64) {
	ticks = map[string]uint64{}
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 13 || !physical(f[2]) {
			continue
		}
		rs, err1 := strconv.ParseUint(f[5], 10, 64)
		ws, err2 := strconv.ParseUint(f[9], 10, 64)
		io, err3 := strconv.ParseUint(f[12], 10, 64)
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		read += rs * 512
		write += ws * 512
		ticks[f[2]] = io
	}
	if len(ticks) == 0 {
		return 0, 0, nil
	}
	return read, write, ticks
}

func parseIOStat(s string, physical func(string) bool) (read, write uint64, ok bool) {
	var maxR, maxW uint64
	phys := false
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		var r, w uint64
		for _, kv := range f[1:] {
			if v, found := strings.CutPrefix(kv, "rbytes="); found {
				r, _ = strconv.ParseUint(v, 10, 64)
			} else if v, found := strings.CutPrefix(kv, "wbytes="); found {
				w, _ = strconv.ParseUint(v, 10, 64)
			}
		}
		ok = true
		if r > maxR {
			maxR = r
		}
		if w > maxW {
			maxW = w
		}
		if physical(f[0]) {
			phys = true
			read += r
			write += w
		}
	}
	if !phys {
		return maxR, maxW, ok
	}
	return read, write, ok
}

func diskBusyPct(prev, cur map[string]uint64, elapsed time.Duration) (float64, bool) {
	if prev == nil || cur == nil || elapsed <= 0 {
		return 0, false
	}
	busiest, seen := 0.0, false
	for name, t := range cur {
		p, ok := prev[name]
		if !ok || t < p {
			continue
		}
		seen = true
		if pct := float64(t-p) / float64(elapsed.Milliseconds()) * 100; pct > busiest {
			busiest = pct
		}
	}
	return clampPct(busiest), seen
}

func blockNamePhysical(name string) bool {
	_, err := os.Stat(filepath.Join("/sys/block", name, "device"))
	return err == nil
}

func blockDevicePhysical(majmin string) bool {
	_, err := os.Stat(filepath.Join("/sys/dev/block", majmin, "device"))
	return err == nil
}

func inContainer(root string) bool {
	if b, err := os.ReadFile(filepath.Join(root, "run/systemd/container")); err == nil && strings.TrimSpace(string(b)) != "" {
		return true
	}
	if b, err := os.ReadFile(filepath.Join(root, "proc/1/environ")); err == nil {
		for _, kv := range strings.Split(string(b), "\x00") {
			if strings.HasPrefix(kv, "container=") && len(kv) > len("container=") {
				return true
			}
		}
	}
	return false
}
