//go:build linux

package metrics

import (
	"math"
	"testing"
)

func memValue(pts []Point, name string) (float64, bool) {
	for _, p := range pts {
		if p.Name == name {
			return p.Value, true
		}
	}
	return 0, false
}

func TestMemPointsUsesMemAvailable(t *testing.T) {
	pts := memPointsFrom("MemTotal: 1000 kB\nMemFree: 100 kB\nMemAvailable: 600 kB\nBuffers: 50 kB\nCached: 200 kB\n")
	used, ok := memValue(pts, "host.mem.used_pct")
	if !ok || math.Abs(used-40) > 1e-9 {
		t.Fatalf("used_pct = %v %v, want 40", used, ok)
	}
}

func TestMemPointsFallsBackWithoutMemAvailable(t *testing.T) {
	pts := memPointsFrom("MemTotal: 1000 kB\nMemFree: 100 kB\nBuffers: 50 kB\nCached: 200 kB\nSReclaimable: 50 kB\n")
	avail, ok := memValue(pts, "host.mem.available_kb")
	if !ok || avail != 400 {
		t.Fatalf("available_kb = %v %v, want 400", avail, ok)
	}
	used, ok := memValue(pts, "host.mem.used_pct")
	if !ok || math.Abs(used-60) > 1e-9 {
		t.Fatalf("used_pct = %v %v, want 60", used, ok)
	}
}

func TestMemPointsFallbackNeverExceedsTotal(t *testing.T) {
	pts := memPointsFrom("MemTotal: 1000 kB\nMemFree: 900 kB\nCached: 500 kB\n")
	used, ok := memValue(pts, "host.mem.used_pct")
	if !ok || used != 0 {
		t.Fatalf("used_pct = %v %v, want 0", used, ok)
	}
}

func TestMemPointsSkipsUsedWhenFreeUnknown(t *testing.T) {
	pts := memPointsFrom("MemTotal: 1000 kB\nSwapTotal: 0 kB\n")
	if _, ok := memValue(pts, "host.mem.used_pct"); ok {
		t.Fatal("used_pct emitted without any free-memory field")
	}
	if _, ok := memValue(pts, "host.mem.available_kb"); ok {
		t.Fatal("available_kb emitted without any free-memory field")
	}
	if total, ok := memValue(pts, "host.mem.total_kb"); !ok || total != 1000 {
		t.Fatalf("total_kb = %v %v, want 1000", total, ok)
	}
}
