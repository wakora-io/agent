package anomaly

import (
	"testing"
	"time"
)

func feed(d *Detector, metric string, values []float64, start time.Time) []*Anomaly {
	var fired []*Anomaly
	for i, v := range values {
		if a := d.Observe(metric, nil, v, start.Add(time.Duration(i)*10*time.Second)); a != nil {
			fired = append(fired, a)
		}
	}
	return fired
}

func flat(n int, v float64) []float64 {
	out := make([]float64, n)
	for i := range out {
		out[i] = v
	}
	return out
}

func TestStableSeriesNeverFires(t *testing.T) {
	d := New()
	if fired := feed(d, "m", flat(100, 10), time.Now()); len(fired) != 0 {
		t.Fatalf("stable series fired %d anomalies", len(fired))
	}
}

func TestSpikeFiresOnceAfterSustain(t *testing.T) {
	d := New()
	values := append(flat(minSamples+2, 10), flat(6, 100)...)
	fired := feed(d, "m", values, time.Now())
	if len(fired) != 1 {
		t.Fatalf("want exactly 1 anomaly, got %d", len(fired))
	}
	a := fired[0]
	if a.Z < zThreshold {
		t.Fatalf("z=%v below threshold", a.Z)
	}
	if a.Baseline > 15 {
		t.Fatalf("baseline contaminated by spike: %v", a.Baseline)
	}
}

func TestNoFireDuringWarmup(t *testing.T) {
	d := New()
	values := append(flat(5, 10), flat(5, 1000)...)
	if fired := feed(d, "m", values, time.Now()); len(fired) != 0 {
		t.Fatalf("fired during warmup")
	}
}

func TestCooldownBlocksSecondFire(t *testing.T) {
	d := New()
	base := time.Now()
	values := append(flat(minSamples+2, 10), flat(4, 100)...)
	values = append(values, flat(5, 10)...)
	values = append(values, flat(4, 100)...)
	fired := feed(d, "m", values, base)
	if len(fired) != 1 {
		t.Fatalf("cooldown violated: %d fires", len(fired))
	}
}

func TestSecondFireAfterCooldown(t *testing.T) {
	d := New()
	base := time.Now()
	first := append(flat(minSamples+2, 10), flat(4, 100)...)
	fired := feed(d, "m", first, base)
	if len(fired) != 1 {
		t.Fatalf("setup: want 1 fire, got %d", len(fired))
	}
	later := base.Add(cooldown + time.Hour)
	second := append(flat(5, 10), flat(4, 100)...)
	fired = feed(d, "m", second, later)
	if len(fired) != 1 {
		t.Fatalf("want fire after cooldown, got %d", len(fired))
	}
}

func TestNewNormalRebaseline(t *testing.T) {
	d := New()
	values := append(flat(minSamples+2, 10), flat(adoptAfter+1, 100)...)
	fired := feed(d, "m", values, time.Now())
	if len(fired) != 1 {
		t.Fatalf("want 1 fire before rebaseline, got %d", len(fired))
	}
	later := flat(10, 100)
	if fired := feed(d, "m", later, time.Now().Add(24*time.Hour)); len(fired) != 0 {
		t.Fatalf("fired on adopted new normal")
	}
}

func TestSeriesAreIndependent(t *testing.T) {
	d := New()
	base := time.Now()
	for i := 0; i < minSamples+2; i++ {
		ts := base.Add(time.Duration(i) * 10 * time.Second)
		d.Observe("m", map[string]string{"mount": "/"}, 10, ts)
		d.Observe("m", map[string]string{"mount": "/data"}, 500, ts)
	}
	var fired int
	for i := 0; i < 4; i++ {
		ts := base.Add(time.Duration(minSamples+2+i) * 10 * time.Second)
		if a := d.Observe("m", map[string]string{"mount": "/"}, 100, ts); a != nil {
			fired++
			if a.Tags["mount"] != "/" {
				t.Fatalf("wrong series fired: %v", a.Tags)
			}
		}
		if a := d.Observe("m", map[string]string{"mount": "/data"}, 500, ts); a != nil {
			t.Fatalf("independent series fired")
		}
	}
	if fired != 1 {
		t.Fatalf("want 1 fire on /, got %d", fired)
	}
}
