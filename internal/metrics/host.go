package metrics

import (
	"runtime"
	"sync"
	"time"
)

type Point struct {
	Name  string
	Value float64
	Tags  map[string]string
}

type Collector struct {
	mu           sync.Mutex
	prevCPUIdle  uint64
	prevCPUTotal uint64
	prevNetRx    uint64
	prevNetTx    uint64
	prevNetAt    time.Time
	hasPrev      bool
	prevTop      map[string]topSample
	prevTopAt    time.Time
}

type topSample struct {
	ticks uint64
	io    uint64
}

func NewCollector() *Collector {
	return &Collector{}
}

func (c *Collector) Collect() (int64, []Point) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	var pts []Point
	pts = append(pts, loadPoints()...)
	pts = append(pts, memPoints()...)
	pts = append(pts, uptimePoints()...)
	pts = append(pts, diskPoints()...)
	pts = append(pts, c.cpuPoints()...)
	pts = append(pts, c.netPoints(now)...)
	pts = append(pts, c.topPoints(now)...)
	cores := float64(runtime.NumCPU())
	pts = append(pts, Point{Name: "host.cpu.cores", Value: cores})
	for _, p := range pts {
		if p.Name == "host.load1" {
			pts = append(pts, Point{Name: "host.load1_per_core", Value: p.Value / cores})
			break
		}
	}
	c.hasPrev = true
	return now.Unix(), pts
}

func cpuUsedPct(total, idle, prevTotal, prevIdle uint64) (float64, bool) {
	if total <= prevTotal || idle < prevIdle {
		return 0, false
	}
	dTotal := float64(total - prevTotal)
	dIdle := float64(idle - prevIdle)
	used := (dTotal - dIdle) / dTotal * 100
	if used < 0 {
		used = 0
	} else if used > 100 {
		used = 100
	}
	return used, true
}
