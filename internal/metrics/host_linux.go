//go:build linux

package metrics

import (
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func loadPoints() []Point {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return nil
	}
	f := strings.Fields(string(b))
	if len(f) < 3 {
		return nil
	}
	names := []string{"host.load1", "host.load5", "host.load15"}
	var pts []Point
	for i, n := range names {
		if v, err := strconv.ParseFloat(f[i], 64); err == nil {
			pts = append(pts, Point{Name: n, Value: v})
		}
	}
	return pts
}

func memPoints() []Point {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return nil
	}
	return memPointsFrom(string(b))
}

func memPointsFrom(meminfo string) []Point {
	vals := map[string]float64{}
	for _, line := range strings.Split(meminfo, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		if v, err := strconv.ParseFloat(f[1], 64); err == nil {
			vals[strings.TrimSuffix(f[0], ":")] = v
		}
	}
	var pts []Point
	total, hasTotal := vals["MemTotal"]
	if hasTotal {
		pts = append(pts, Point{Name: "host.mem.total_kb", Value: total})
	}
	avail, hasAvail := vals["MemAvailable"]
	if !hasAvail {
		if free, ok := vals["MemFree"]; ok {
			avail = free + vals["Buffers"] + vals["Cached"] + vals["SReclaimable"]
			hasAvail = true
		}
	}
	if hasAvail {
		if hasTotal && avail > total {
			avail = total
		}
		pts = append(pts, Point{Name: "host.mem.available_kb", Value: avail})
		if total > 0 {
			pts = append(pts, Point{Name: "host.mem.used_pct", Value: (total - avail) / total * 100})
		}
	}
	if st := vals["SwapTotal"]; st > 0 {
		pts = append(pts, Point{Name: "host.swap.used_pct", Value: (st - vals["SwapFree"]) / st * 100})
	}
	return pts
}

func uptimePoints() []Point {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return nil
	}
	f := strings.Fields(string(b))
	if len(f) < 1 {
		return nil
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return nil
	}
	return []Point{{Name: "host.uptime_sec", Value: v}}
}

var realFilesystems = map[string]bool{
	"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true,
	"f2fs": true, "zfs": true, "vfat": true, "exfat": true, "ntfs": true, "ntfs3": true, "fuseblk": true,
}

func diskPoints() []Point {
	b, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return nil
	}
	hostRO := hostMountReadOnly()
	var pts []Point
	seenDev := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || !realFilesystems[f[2]] || seenDev[f[0]] {
			continue
		}
		mount := strings.ReplaceAll(f[1], "\\040", " ")
		var st syscall.Statfs_t
		if err := syscall.Statfs(mount, &st); err != nil || st.Blocks == 0 {
			continue
		}
		seenDev[f[0]] = true
		bsize := uint64(st.Bsize)
		total := float64(st.Blocks * bsize)
		used := float64((st.Blocks - st.Bfree) * bsize)
		avail := float64(st.Bavail * bsize)
		tags := map[string]string{"mount": mount}
		pts = append(pts,
			Point{Name: "host.disk.total_bytes", Value: total, Tags: tags},
			Point{Name: "host.disk.used_bytes", Value: used, Tags: tags},
			Point{Name: "host.disk.used_pct", Value: (total - avail) / total * 100, Tags: tags},
		)
		if readOnlyWatched(f[2]) {
			ro, known := hostRO[mount]
			if !known {
				ro = fsReadOnly(&st)
			}
			readonly := 0.0
			if ro {
				readonly = 1
			}
			pts = append(pts, Point{Name: "host.disk.readonly", Value: readonly, Tags: tags})
		}
	}
	return pts
}

func readOnlyWatched(fstype string) bool {
	return fstype != "vfat"
}

func fsReadOnly(st *syscall.Statfs_t) bool {
	return st.Flags&syscall.MS_RDONLY != 0
}

func hostMountReadOnly() map[string]bool {
	b, err := os.ReadFile("/proc/1/mounts")
	if err != nil {
		return nil
	}
	return parseMountReadOnly(string(b))
}

func parseMountReadOnly(table string) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(table, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || !realFilesystems[f[2]] {
			continue
		}
		mount := strings.ReplaceAll(f[1], "\\040", " ")
		ro := false
		for _, o := range strings.Split(f[3], ",") {
			if o == "ro" {
				ro = true
				break
			}
		}
		out[mount] = ro
	}
	return out
}

func (c *Collector) cpuPoints() []Point {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return nil
	}
	line, _, _ := strings.Cut(string(b), "\n")
	f := strings.Fields(line)
	if len(f) < 5 || f[0] != "cpu" {
		return nil
	}
	fields := f[1:]
	if len(fields) > 8 {
		fields = fields[:8]
	}
	var total, idle uint64
	for i, s := range fields {
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			continue
		}
		total += v
		if i == 3 || i == 4 {
			idle += v
		}
	}
	prevTotal, prevIdle := c.prevCPUTotal, c.prevCPUIdle
	c.prevCPUTotal, c.prevCPUIdle = total, idle
	if !c.hasPrev {
		return nil
	}
	used, ok := cpuUsedPct(total, idle, prevTotal, prevIdle)
	if !ok {
		return nil
	}
	return []Point{{Name: "host.cpu.used_pct", Value: used}}
}

func (c *Collector) netPoints(now time.Time) []Point {
	b, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return nil
	}
	rx, tx := sumUplinks(string(b), sysNetProbe{"/sys/class/net"})
	prevRx, prevTx, prevAt := c.prevNetRx, c.prevNetTx, c.prevNetAt
	c.prevNetRx, c.prevNetTx, c.prevNetAt = rx, tx, now
	if !c.hasPrev || prevAt.IsZero() {
		return nil
	}
	elapsed := now.Sub(prevAt).Seconds()
	if elapsed <= 0 || rx < prevRx || tx < prevTx {
		return nil
	}
	return []Point{
		{Name: "host.net.rx_bytes_per_sec", Value: float64(rx-prevRx) / elapsed},
		{Name: "host.net.tx_bytes_per_sec", Value: float64(tx-prevTx) / elapsed},
	}
}

type netProbe interface {
	hasDevice(name string) bool
	isBridge(name string) bool
	isBridgePort(name string) bool
}

type sysNetProbe struct{ root string }

func (s sysNetProbe) exists(name, leaf string) bool {
	_, err := os.Stat(s.root + "/" + name + "/" + leaf)
	return err == nil
}

func (s sysNetProbe) hasDevice(name string) bool    { return s.exists(name, "device") }
func (s sysNetProbe) isBridge(name string) bool     { return s.exists(name, "bridge") }
func (s sysNetProbe) isBridgePort(name string) bool { return s.exists(name, "brport") }

func sumUplinks(netdev string, probe netProbe) (rx, tx uint64) {
	type counters struct{ rx, tx uint64 }
	ifaces := map[string]counters{}
	var order []string
	lines := strings.Split(netdev, "\n")
	if len(lines) < 3 {
		return 0, 0
	}
	for _, line := range lines[2:] {
		name, rest, ok := strings.Cut(line, ":")
		name = strings.TrimSpace(name)
		if !ok || name == "lo" {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 9 {
			continue
		}
		var c counters
		if v, err := strconv.ParseUint(f[0], 10, 64); err == nil {
			c.rx = v
		}
		if v, err := strconv.ParseUint(f[8], 10, 64); err == nil {
			c.tx = v
		}
		ifaces[name] = c
		order = append(order, name)
	}
	physical := false
	for _, name := range order {
		if probe.hasDevice(name) {
			physical = true
			break
		}
	}
	for _, name := range order {
		if physical {
			if !probe.hasDevice(name) {
				continue
			}
		} else if probe.isBridge(name) || probe.isBridgePort(name) {
			continue
		}
		rx += ifaces[name].rx
		tx += ifaces[name].tx
	}
	return rx, tx
}
