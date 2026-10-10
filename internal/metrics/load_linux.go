//go:build linux

package metrics

import (
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const loadSampleEvery = 5 * time.Second

var loadDecay = [3]float64{
	math.Exp(-5.0 / 60),
	math.Exp(-5.0 / 300),
	math.Exp(-5.0 / 900),
}

type loadAverager struct {
	mu     sync.Mutex
	avg    [3]float64
	primed bool
}

func (l *loadAverager) observe(n float64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.primed {
		l.avg = [3]float64{n, n, n}
		l.primed = true
		return
	}
	for i, e := range loadDecay {
		l.avg[i] = l.avg[i]*e + n*(1-e)
	}
}

func (l *loadAverager) value() ([3]float64, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.avg, l.primed
}

var (
	containerLoad     loadAverager
	containerLoadOnce sync.Once
)

func containerLoadPoints() []Point {
	containerLoadOnce.Do(func() {
		go func() {
			self := os.Getpid()
			containerLoad.observe(float64(countActiveTasks("/proc", self)))
			t := time.NewTicker(loadSampleEvery)
			defer t.Stop()
			for range t.C {
				containerLoad.observe(float64(countActiveTasks("/proc", self)))
			}
		}()
	})
	avg, ok := containerLoad.value()
	if !ok {
		return nil
	}
	return []Point{
		{Name: "host.load1", Value: round2f(avg[0])},
		{Name: "host.load5", Value: round2f(avg[1])},
		{Name: "host.load15", Value: round2f(avg[2])},
	}
}

func round2f(v float64) float64 {
	return math.Round(v*100) / 100
}

func countActiveTasks(proc string, self int) int {
	pids, err := os.ReadDir(proc)
	if err != nil {
		return 0
	}
	n := 0
	for _, p := range pids {
		pid, err := strconv.Atoi(p.Name())
		if err != nil || pid == self {
			continue
		}
		tasks, err := os.ReadDir(filepath.Join(proc, p.Name(), "task"))
		if err != nil {
			continue
		}
		for _, t := range tasks {
			b, err := os.ReadFile(filepath.Join(proc, p.Name(), "task", t.Name(), "stat"))
			if err != nil {
				continue
			}
			if s := taskState(string(b)); s == 'R' || s == 'D' {
				n++
			}
		}
	}
	return n
}

func taskState(stat string) byte {
	i := strings.LastIndexByte(stat, ')')
	if i < 0 || i+2 >= len(stat) {
		return 0
	}
	return stat[i+2]
}

func (c *Collector) cpuPressurePoints(now time.Time) []Point {
	path := "/proc/pressure/cpu"
	if inContainer("/") {
		path = "/sys/fs/cgroup/cpu.pressure"
	}
	b, err := os.ReadFile(path)
	if err != nil {
		c.cpuPSIAt = time.Time{}
		return nil
	}
	total, ok := parsePSITotal(string(b))
	if !ok {
		c.cpuPSIAt = time.Time{}
		return nil
	}
	prev, prevAt := c.cpuPSI, c.cpuPSIAt
	c.cpuPSI, c.cpuPSIAt = total, now
	if prevAt.IsZero() || total < prev {
		return nil
	}
	elapsed := now.Sub(prevAt)
	if elapsed <= 0 {
		return nil
	}
	pct := float64(total-prev) / float64(elapsed.Microseconds()) * 100
	return []Point{{Name: "host.cpu.pressure_pct", Value: clampPct(pct)}}
}
