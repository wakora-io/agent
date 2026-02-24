//go:build darwin

package metrics

import (
	"encoding/binary"
	"time"

	"golang.org/x/sys/unix"
)

func loadPoints() []Point {
	raw, err := unix.SysctlRaw("vm.loadavg")
	if err != nil || len(raw) < 12 {
		return nil
	}
	fscale := 2048.0
	switch {
	case len(raw) >= 24:
		if v := binary.LittleEndian.Uint64(raw[16:24]); v != 0 {
			fscale = float64(v)
		}
	case len(raw) >= 16:
		if v := binary.LittleEndian.Uint32(raw[12:16]); v != 0 {
			fscale = float64(v)
		}
	}
	names := []string{"host.load1", "host.load5", "host.load15"}
	var pts []Point
	for i, n := range names {
		v := float64(binary.LittleEndian.Uint32(raw[i*4:i*4+4])) / fscale
		pts = append(pts, Point{Name: n, Value: v})
	}
	return pts
}

func memPoints() []Point {
	total, err := unix.SysctlUint64("hw.memsize")
	if err != nil || total == 0 {
		return nil
	}
	pts := []Point{{Name: "host.mem.total_kb", Value: float64(total) / 1024}}
	if raw, err := unix.SysctlRaw("vm.swapusage"); err == nil && len(raw) >= 24 {
		swapTotal := binary.LittleEndian.Uint64(raw[0:8])
		swapUsed := binary.LittleEndian.Uint64(raw[16:24])
		if swapTotal > 0 {
			pts = append(pts, Point{Name: "host.swap.used_pct", Value: float64(swapUsed) / float64(swapTotal) * 100})
		}
	}
	return append(pts, vmMemPoints(total)...)
}

func uptimePoints() []Point {
	tv, err := unix.SysctlTimeval("kern.boottime")
	if err != nil || tv.Sec == 0 {
		return nil
	}
	up := time.Now().Unix() - int64(tv.Sec)
	if up < 0 {
		return nil
	}
	return []Point{{Name: "host.uptime_sec", Value: float64(up)}}
}

var skipFstype = map[string]bool{"devfs": true, "autofs": true, "none": true}

func diskPoints() []Point {
	n, err := unix.Getfsstat(nil, unix.MNT_NOWAIT)
	if err != nil || n == 0 {
		return nil
	}
	buf := make([]unix.Statfs_t, n)
	if _, err := unix.Getfsstat(buf, unix.MNT_NOWAIT); err != nil {
		return nil
	}
	var pts []Point
	for i := range buf {
		fs := &buf[i]
		if fs.Flags&unix.MNT_LOCAL == 0 || skipFstype[cstr(fs.Fstypename[:])] {
			continue
		}
		bsize := uint64(fs.Bsize)
		total := float64(fs.Blocks * bsize)
		if total == 0 {
			continue
		}
		used := float64((fs.Blocks - fs.Bfree) * bsize)
		avail := float64(fs.Bavail * bsize)
		tags := map[string]string{"mount": cstr(fs.Mntonname[:])}
		pts = append(pts,
			Point{Name: "host.disk.total_bytes", Value: total, Tags: tags},
			Point{Name: "host.disk.used_bytes", Value: used, Tags: tags},
			Point{Name: "host.disk.used_pct", Value: (total - avail) / total * 100, Tags: tags},
		)
	}
	return pts
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
