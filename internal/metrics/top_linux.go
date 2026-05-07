//go:build linux

package metrics

import (
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const topN = 5
const clkTck = 100

type topAgg struct {
	ticks uint64
	rss   uint64
	io    uint64
}

func (c *Collector) topPoints(now time.Time) []Point {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	cur := map[string]*topAgg{}
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		base := "/proc/" + e.Name()
		stat, err := os.ReadFile(base + "/stat")
		if err != nil {
			continue
		}
		comm, ticks, rssPages, ok := parseProcStat(string(stat))
		if !ok {
			continue
		}
		a := cur[comm]
		if a == nil {
			a = &topAgg{}
			cur[comm] = a
		}
		a.ticks += ticks
		a.rss += rssPages * uint64(os.Getpagesize())
		if raw, err := os.ReadFile(base + "/io"); err == nil {
			a.io += procIOBytes(string(raw))
		}
	}
	prev := c.prevTop
	prevAt := c.prevTopAt
	next := make(map[string]topSample, len(cur))
	for name, a := range cur {
		next[name] = topSample{ticks: a.ticks, io: a.io}
	}
	c.prevTop = next
	c.prevTopAt = now

	var pts []Point
	type row struct {
		name string
		v    float64
	}
	pick := func(rows []row, metric string) {
		sort.Slice(rows, func(i, j int) bool { return rows[i].v > rows[j].v })
		if len(rows) > topN {
			rows = rows[:topN]
		}
		for _, r := range rows {
			pts = append(pts, Point{Name: metric, Value: r.v, Tags: map[string]string{"proc": r.name}})
		}
	}

	var memRows []row
	for name, a := range cur {
		if a.rss > 0 {
			memRows = append(memRows, row{name, float64(a.rss)})
		}
	}
	pick(memRows, "host.top.mem_bytes")

	dt := now.Sub(prevAt).Seconds()
	if prev == nil || dt <= 0 {
		return pts
	}
	var cpuRows, ioRows []row
	for name, a := range cur {
		p, had := prev[name]
		if !had {
			continue
		}
		if a.ticks > p.ticks {
			pct := float64(a.ticks-p.ticks) / clkTck / dt * 100
			cpuRows = append(cpuRows, row{name, float64(int(pct*10+0.5)) / 10})
		}
		if a.io > p.io {
			ioRows = append(ioRows, row{name, float64(int(float64(a.io-p.io)/dt + 0.5))})
		}
	}
	pick(cpuRows, "host.top.cpu_pct")
	pick(ioRows, "host.top.io_bps")
	return pts
}

func parseProcStat(s string) (string, uint64, uint64, bool) {
	open := strings.IndexByte(s, '(')
	close := strings.LastIndexByte(s, ')')
	if open < 0 || close <= open {
		return "", 0, 0, false
	}
	comm := s[open+1 : close]
	f := strings.Fields(s[close+1:])
	if len(f) < 22 {
		return "", 0, 0, false
	}
	ut, _ := strconv.ParseUint(f[11], 10, 64)
	st, _ := strconv.ParseUint(f[12], 10, 64)
	rss, _ := strconv.ParseUint(f[21], 10, 64)
	return comm, ut + st, rss, true
}

func procIOBytes(s string) uint64 {
	var total uint64
	for _, line := range strings.Split(s, "\n") {
		if v, ok := strings.CutPrefix(line, "read_bytes: "); ok {
			if n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64); err == nil {
				total += n
			}
		}
		if v, ok := strings.CutPrefix(line, "write_bytes: "); ok {
			if n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64); err == nil {
				total += n
			}
		}
	}
	return total
}
