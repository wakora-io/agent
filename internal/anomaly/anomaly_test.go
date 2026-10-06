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

func TestExcludedFamilyNeverFires(t *testing.T) {
	d := New()
	values := append(flat(minSamples+2, 10), flat(6, 900)...)
	if fired := feed(d, "host.top.cpu_pct", values, time.Now()); len(fired) != 0 {
		t.Fatalf("excluded family fired %d", len(fired))
	}
	if len(d.states) != 0 {
		t.Fatalf("excluded family kept state")
	}
}

func TestTinyChangeOnZeroBaselineStaysQuiet(t *testing.T) {
	d := New()
	values := append(flat(minSamples+2, 0), flat(6, 0.02)...)
	if fired := feed(d, "host.swap.used_pct", values, time.Now()); len(fired) != 0 {
		t.Fatalf("zero sigma tiny change fired %d", len(fired))
	}
}

func TestPercentNeedsTenPoints(t *testing.T) {
	d := New()
	values := append(flat(minSamples+2, 5), flat(6, 12)...)
	if fired := feed(d, "host.cpu.used_pct", values, time.Now()); len(fired) != 0 {
		t.Fatalf("7 points fired")
	}
	d = New()
	values = append(flat(minSamples+2, 5), flat(6, 40)...)
	if fired := feed(d, "host.cpu.used_pct", values, time.Now()); len(fired) != 1 {
		t.Fatalf("35 points want 1 fire, got %d", len(fired))
	}
}

func TestDropIsQuietForUpOnlyClass(t *testing.T) {
	d := New()
	values := append(flat(minSamples+2, 80), flat(6, 5)...)
	if fired := feed(d, "host.cpu.used_pct", values, time.Now()); len(fired) != 0 {
		t.Fatalf("cpu drop fired")
	}
	d = New()
	values = append(flat(minSamples+2, 50<<20), flat(6, 0)...)
	if fired := feed(d, "host.net.rx_bytes_per_sec", values, time.Now()); len(fired) != 1 {
		t.Fatalf("traffic collapse want 1 fire, got %d", len(fired))
	}
}

func TestServerConfigOverrides(t *testing.T) {
	d := New()
	d.SetConfig(Config{Exclude: []string{"host.cpu.%"}})
	values := append(flat(minSamples+2, 5), flat(6, 90)...)
	if fired := feed(d, "host.cpu.used_pct", values, time.Now()); len(fired) != 0 {
		t.Fatalf("server exclusion ignored")
	}
	if fired := feed(d, "host.top.cpu_pct", values, time.Now()); len(fired) != 1 {
		t.Fatalf("server exclude list must replace the default one")
	}
	d.SetConfig(Config{})
	if len(d.cfg.Classes) == 0 || d.cfg.Z != zThreshold {
		t.Fatalf("empty config must fall back to defaults")
	}
}

func TestLike(t *testing.T) {
	cases := []struct {
		p, s string
		want bool
	}{
		{"host.top.%", "host.top.io_bps", true},
		{"host.top.%", "host.topx", false},
		{"%.max_ms", "apm.backend.max_ms", true},
		{"%_pct", "host.cpu.used_pct", true},
		{"%_pct", "host.cpu.used_pctx", false},
		{"host.load%per_core", "host.load1_per_core", true},
		{"host.load1", "host.load1_per_core", false},
		{"%uptime%", "svc.proxmox.guest.uptime", true},
		{"%", "anything", true},
		{"a%b%c", "axxbyyc", true},
		{"a%b%c", "axxcyyb", false},
		{"ab%ba", "aba", false},
	}
	for _, c := range cases {
		if got := like(c.p, c.s); got != c.want {
			t.Fatalf("like(%q, %q) = %v, want %v", c.p, c.s, got, c.want)
		}
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
