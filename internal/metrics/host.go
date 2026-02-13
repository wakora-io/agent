package metrics

import (
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Point struct {
	Name  string
	Value float64
	Tags  map[string]string
}

type Collector struct {
	prevCPUIdle  uint64
	prevCPUTotal uint64
	prevNetRx    uint64
	prevNetTx    uint64
	prevNetAt    time.Time
	hasPrev      bool
}

func NewCollector() *Collector {
	return &Collector{}
}

func (c *Collector) Collect() (int64, []Point) {
	now := time.Now()
	var pts []Point
	pts = append(pts, loadPoints()...)
	pts = append(pts, memPoints()...)
	pts = append(pts, uptimePoints()...)
	pts = append(pts, diskPoints()...)
	pts = append(pts, c.cpuPoints()...)
	pts = append(pts, c.netPoints(now)...)
	c.hasPrev = true
	return now.Unix(), pts
}

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
	vals := map[string]float64{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		if v, err := strconv.ParseFloat(f[1], 64); err == nil {
			vals[strings.TrimSuffix(f[0], ":")] = v
		}
	}
	total := vals["MemTotal"]
	avail := vals["MemAvailable"]
	pts := []Point{
		{Name: "host.mem.total_kb", Value: total},
		{Name: "host.mem.available_kb", Value: avail},
	}
	if total > 0 {
		pts = append(pts, Point{Name: "host.mem.used_pct", Value: (total - avail) / total * 100})
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
	"f2fs": true, "zfs": true, "vfat": true, "exfat": true, "ntfs": true, "fuseblk": true,
}

func diskPoints() []Point {
	b, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return nil
	}
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
	}
	return pts
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
	var total, idle uint64
	for i, s := range f[1:] {
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
	if !c.hasPrev || total <= prevTotal {
		return nil
	}
	dTotal := float64(total - prevTotal)
	dIdle := float64(idle - prevIdle)
	return []Point{{Name: "host.cpu.used_pct", Value: (dTotal - dIdle) / dTotal * 100}}
}

func (c *Collector) netPoints(now time.Time) []Point {
	b, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return nil
	}
	var rx, tx uint64
	lines := strings.Split(string(b), "\n")
	for _, line := range lines[2:] {
		name, rest, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(name) == "lo" {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 9 {
			continue
		}
		if v, err := strconv.ParseUint(f[0], 10, 64); err == nil {
			rx += v
		}
		if v, err := strconv.ParseUint(f[8], 10, 64); err == nil {
			tx += v
		}
	}
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
