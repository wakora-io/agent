package metrics

import (
	"sync"
	"testing"
)

func TestCpuUsedPct(t *testing.T) {
	cases := []struct {
		name                             string
		total, idle, prevTotal, prevIdle uint64
		want                             float64
		ok                               bool
	}{
		{"half busy", 2000, 1500, 1000, 1000, 50, true},
		{"fully idle", 2000, 2000, 1000, 1000, 0, true},
		{"fully busy", 2000, 1000, 1000, 1000, 100, true},
		{"first-ish equal total", 1000, 1000, 1000, 1000, 0, false},
		{"total went backwards", 900, 800, 1000, 700, 0, false},
		{"idle went backwards (iowait underflow)", 2000, 900, 1000, 1000, 0, false},
		{"idle grew more than total -> clamp 0", 2000, 2500, 1000, 1000, 0, true},
	}
	for _, c := range cases {
		got, ok := cpuUsedPct(c.total, c.idle, c.prevTotal, c.prevIdle)
		if ok != c.ok || (ok && got != c.want) {
			t.Fatalf("%s: got (%v,%v) want (%v,%v)", c.name, got, ok, c.want, c.ok)
		}
	}
}

func TestCollectConcurrent(t *testing.T) {
	c := NewCollector()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				c.Collect()
			}
		}()
	}
	wg.Wait()
}
