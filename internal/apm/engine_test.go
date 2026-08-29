//go:build linux

package apm

import "testing"

func TestPercentileInterpolation(t *testing.T) {
	a := &portAgg{count: 100, maxNs: 90e6}
	a.buckets[6] = 100
	p50 := percentile(a, 0.50)
	if p50 <= 50 || p50 >= 90 {
		t.Fatalf("p50 out of bucket range: %v", p50)
	}
	p95 := percentile(a, 0.95)
	if p95 <= p50 || p95 > 90 {
		t.Fatalf("p95: %v (p50 %v)", p95, p50)
	}
}

func TestPercentileEmpty(t *testing.T) {
	if v := percentile(&portAgg{}, 0.5); v != 0 {
		t.Fatalf("empty agg: %v", v)
	}
}

func TestPercentileSpreadAndClamp(t *testing.T) {
	a := &portAgg{count: 100, maxNs: 3000e6}
	a.buckets[2] = 90
	a.buckets[11] = 10
	p50 := percentile(a, 0.50)
	if p50 < 2 || p50 > 5 {
		t.Fatalf("p50 should sit in the 2-5ms bucket: %v", p50)
	}
	p95 := percentile(a, 0.95)
	if p95 < 2500 || p95 > 3000 {
		t.Fatalf("p95 should interpolate in 2500-5000 and clamp to max 3000: %v", p95)
	}
}
