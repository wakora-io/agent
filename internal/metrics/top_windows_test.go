//go:build windows

package metrics

import (
	"testing"
	"time"
)

func TestTopFromAggregatesAndRanks(t *testing.T) {
	c := NewCollector()
	t0 := time.Unix(1000, 0)
	first := c.topFrom(aggregateTop([]procSample{
		{name: "w3wp.exe", cpu: 0, rss: 300 << 20, io: 0},
		{name: "w3wp.exe", cpu: 0, rss: 200 << 20, io: 0},
		{name: "sqlservr.exe", cpu: 0, rss: 900 << 20, io: 0},
	}), t0)
	for _, p := range first {
		if p.Name != "host.top.mem_bytes" {
			t.Fatalf("the first sample may only carry memory, got %+v", p)
		}
	}
	second := c.topFrom(aggregateTop([]procSample{
		{name: "w3wp.exe", cpu: 6e8, rss: 300 << 20, io: 10 << 20},
		{name: "w3wp.exe", cpu: 6e8, rss: 200 << 20, io: 0},
		{name: "sqlservr.exe", cpu: 3e8, rss: 900 << 20, io: 60 << 20},
	}), t0.Add(60*time.Second))
	got := map[string]float64{}
	for _, p := range second {
		got[p.Name+"|"+p.Tags["proc"]] = p.Value
	}
	if v := got["host.top.cpu_pct|w3wp.exe"]; v != 200 {
		t.Fatalf("w3wp cpu %v, want 200 (two workers, 60s each over 60s)", v)
	}
	if v := got["host.top.cpu_pct|sqlservr.exe"]; v != 50 {
		t.Fatalf("sqlservr cpu %v, want 50", v)
	}
	if v := got["host.top.mem_bytes|w3wp.exe"]; v != 500<<20 {
		t.Fatalf("w3wp memory %v", v)
	}
	if v := got["host.top.io_bps|sqlservr.exe"]; v != 1048576 {
		t.Fatalf("sqlservr io %v", v)
	}
}

func TestTopPointsReadsTheLiveProcessList(t *testing.T) {
	c := NewCollector()
	now := time.Now()
	pts := c.topPoints(now)
	if len(pts) == 0 {
		t.Fatal("no process memory read on the first sample")
	}
	time.Sleep(300 * time.Millisecond)
	for _, p := range c.topPoints(now.Add(time.Second)) {
		if p.Value < 0 {
			t.Fatalf("negative point %+v", p)
		}
	}
}
