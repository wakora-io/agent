package defs

import (
	"testing"
	"time"

	"wakora.io/agent/internal/protocol"
)

func rateReset() {
	rateMu.Lock()
	rateSeen = map[string]rateMark{}
	rateHist = map[string][]rateMark{}
	rateMu.Unlock()
}

func lastReset() {
	lastMu.Lock()
	lastSeen = map[string]rateMark{}
	lastMu.Unlock()
}

func rateOf(o Outcome, name string) (float64, bool) {
	for _, m := range o.Metrics {
		if m.Name == name {
			return m.Value, true
		}
	}
	return 0, false
}

func TestRatesNeedTwoSamples(t *testing.T) {
	rateReset()
	p := protocol.Probe{Rates: []protocol.RateRule{{Name: "svc.mysql.aborted_connects"}}}
	t0 := time.Unix(1000, 0)

	o := Outcome{Metrics: []protocol.MetricPoint{{Name: "svc.mysql.aborted_connects", Value: 100}}}
	applyRates(&o, "mysql", p, t0)
	if _, ok := rateOf(o, "svc.mysql.aborted_connects_rate"); ok {
		t.Fatal("the first sample of a counter cannot be a rate")
	}

	o = Outcome{Metrics: []protocol.MetricPoint{{Name: "svc.mysql.aborted_connects", Value: 130}}}
	applyRates(&o, "mysql", p, t0.Add(60*time.Second))
	v, ok := rateOf(o, "svc.mysql.aborted_connects_rate")
	if !ok || v != 0.5 {
		t.Fatalf("30 more over 60s is 0.5 per second, got %v (%v)", v, ok)
	}
}

func TestRatesSkipACounterReset(t *testing.T) {
	rateReset()
	p := protocol.Probe{Rates: []protocol.RateRule{{Name: "svc.redis.total_commands_processed"}}}
	t0 := time.Unix(2000, 0)
	o := Outcome{Metrics: []protocol.MetricPoint{{Name: "svc.redis.total_commands_processed", Value: 900}}}
	applyRates(&o, "redis", p, t0)

	o = Outcome{Metrics: []protocol.MetricPoint{{Name: "svc.redis.total_commands_processed", Value: 12}}}
	applyRates(&o, "redis", p, t0.Add(60*time.Second))
	if _, ok := rateOf(o, "svc.redis.total_commands_processed_rate"); ok {
		t.Fatal("a restarted service must not report a negative or huge rate")
	}

	o = Outcome{Metrics: []protocol.MetricPoint{{Name: "svc.redis.total_commands_processed", Value: 72}}}
	applyRates(&o, "redis", p, t0.Add(120*time.Second))
	v, ok := rateOf(o, "svc.redis.total_commands_processed_rate")
	if !ok || v != 1 {
		t.Fatalf("the cycle after a reset counts from the new baseline, got %v (%v)", v, ok)
	}
}

func TestRatesKeepTagsApartAndHonorPer(t *testing.T) {
	rateReset()
	p := protocol.Probe{Rates: []protocol.RateRule{{Name: "svc.docker.group.restarts", Out: "svc.docker.group.restarts_per_hour", Per: "hour"}}}
	t0 := time.Unix(3000, 0)
	first := Outcome{Metrics: []protocol.MetricPoint{
		{Name: "svc.docker.group.restarts", Value: 10, Tags: map[string]string{"image": "nginx"}},
		{Name: "svc.docker.group.restarts", Value: 5, Tags: map[string]string{"image": "redis"}},
	}}
	applyRates(&first, "docker", p, t0)

	second := Outcome{Metrics: []protocol.MetricPoint{
		{Name: "svc.docker.group.restarts", Value: 13, Tags: map[string]string{"image": "nginx"}},
		{Name: "svc.docker.group.restarts", Value: 5, Tags: map[string]string{"image": "redis"}},
	}}
	applyRates(&second, "docker", p, t0.Add(60*time.Second))

	byImage := map[string]float64{}
	for _, m := range second.Metrics {
		if m.Name == "svc.docker.group.restarts_per_hour" {
			byImage[m.Tags["image"]] = m.Value
		}
	}
	if byImage["nginx"] != 180 {
		t.Fatalf("3 restarts a minute is 180 an hour, got %v", byImage["nginx"])
	}
	if byImage["redis"] != 0 {
		t.Fatalf("a quiet group reports zero, not the neighbour's value, got %v", byImage["redis"])
	}
}

func TestDerivedJoinsTwoProbesOfOneService(t *testing.T) {
	lastReset()
	t0 := time.Unix(5000, 0)
	RememberMetrics("mysql", []protocol.MetricPoint{{Name: "svc.mysql.connections", Value: 30}}, t0)
	RememberMetrics("mysql", []protocol.MetricPoint{{Name: "svc.mysql.max_connections", Value: 150}}, t0.Add(5*time.Second))

	rule := protocol.DerivedRule{Name: "svc.mysql.connections_used_pct", Num: "svc.mysql.connections", Den: "svc.mysql.max_connections", Scale: 100}
	out := Derived("mysql", []protocol.DerivedRule{rule}, t0.Add(10*time.Second))
	if len(out) != 1 || out[0].Value != 20 {
		t.Fatalf("30 of 150 connections is 20 percent, got %+v", out)
	}
}

func TestDerivedStaysSilentWithoutBothHalves(t *testing.T) {
	lastReset()
	t0 := time.Unix(6000, 0)
	rule := protocol.DerivedRule{Name: "svc.redis.memory_used_pct", Num: "svc.redis.used_memory", Den: "svc.redis.maxmemory", Scale: 100}

	RememberMetrics("redis", []protocol.MetricPoint{{Name: "svc.redis.used_memory", Value: 900}}, t0)
	if out := Derived("redis", []protocol.DerivedRule{rule}, t0); len(out) != 0 {
		t.Fatalf("a missing limit produces no metric, got %+v", out)
	}

	RememberMetrics("redis", []protocol.MetricPoint{{Name: "svc.redis.maxmemory", Value: 0}}, t0)
	if out := Derived("redis", []protocol.DerivedRule{rule}, t0); len(out) != 0 {
		t.Fatalf("redis without maxmemory reports no limit at all, not 100 percent, got %+v", out)
	}

	RememberMetrics("redis", []protocol.MetricPoint{{Name: "svc.redis.maxmemory", Value: 1800}}, t0)
	out := Derived("redis", []protocol.DerivedRule{rule}, t0.Add(time.Minute))
	if len(out) != 1 || out[0].Value != 50 {
		t.Fatalf("900 of 1800 is half the limit, got %+v", out)
	}

	if out := Derived("redis", []protocol.DerivedRule{rule}, t0.Add(2*rateStale)); len(out) != 0 {
		t.Fatalf("a value nobody refreshed must go quiet, got %+v", out)
	}
}

func TestDerivedKeepsServicesApart(t *testing.T) {
	lastReset()
	t0 := time.Unix(7000, 0)
	RememberMetrics("mysql", []protocol.MetricPoint{{Name: "svc.mysql.connections", Value: 10}}, t0)
	RememberMetrics("postgres", []protocol.MetricPoint{{Name: "svc.mysql.max_connections", Value: 100}}, t0)
	rule := protocol.DerivedRule{Name: "svc.mysql.connections_used_pct", Num: "svc.mysql.connections", Den: "svc.mysql.max_connections", Scale: 100}
	if out := Derived("mysql", []protocol.DerivedRule{rule}, t0); len(out) != 0 {
		t.Fatalf("a neighbour service must not lend its numbers, got %+v", out)
	}
}

func TestWindowCountsEventsOverTheWholeWindow(t *testing.T) {
	rateReset()
	p := protocol.Probe{Rates: []protocol.RateRule{{Name: "svc.docker.group.restarts", Out: "svc.docker.group.restarts_1h", Window: 3600}}}
	t0 := time.Unix(10000, 0)
	tags := map[string]string{"image": "alpine"}

	restarts := 100.0
	var last float64
	var seen bool
	for i := 0; i < 30; i++ {
		if i%10 == 0 && i > 0 {
			restarts++
		}
		o := Outcome{Metrics: []protocol.MetricPoint{{Name: "svc.docker.group.restarts", Value: restarts, Tags: tags}}}
		applyRates(&o, "docker", p, t0.Add(time.Duration(i)*time.Minute))
		if v, ok := rateOf(o, "svc.docker.group.restarts_1h"); ok {
			last, seen = v, true
		}
	}
	if !seen {
		t.Fatal("a window rule must report from the second sample on")
	}
	if last != 2 {
		t.Fatalf("three restarts spread over the window read as the count since its start, got %v", last)
	}
}

func TestWindowHoldsThroughQuietMinutes(t *testing.T) {
	rateReset()
	p := protocol.Probe{Rates: []protocol.RateRule{{Name: "svc.docker.group.restarts", Out: "svc.docker.group.restarts_1h", Window: 3600}}}
	t0 := time.Unix(20000, 0)

	o := Outcome{Metrics: []protocol.MetricPoint{{Name: "svc.docker.group.restarts", Value: 10}}}
	applyRates(&o, "docker", p, t0)
	o = Outcome{Metrics: []protocol.MetricPoint{{Name: "svc.docker.group.restarts", Value: 16}}}
	applyRates(&o, "docker", p, t0.Add(time.Minute))
	v, _ := rateOf(o, "svc.docker.group.restarts_1h")
	if v != 6 {
		t.Fatalf("six restarts in the window, got %v", v)
	}
	// the quiet minute after a burst must NOT read zero - that is exactly what
	// made a per-minute rate useless for a crash loop
	o = Outcome{Metrics: []protocol.MetricPoint{{Name: "svc.docker.group.restarts", Value: 16}}}
	applyRates(&o, "docker", p, t0.Add(2*time.Minute))
	v, _ = rateOf(o, "svc.docker.group.restarts_1h")
	if v != 6 {
		t.Fatalf("a quiet minute must keep the window count, got %v", v)
	}
	// once the burst ages out of the window the count falls back to zero
	o = Outcome{Metrics: []protocol.MetricPoint{{Name: "svc.docker.group.restarts", Value: 16}}}
	applyRates(&o, "docker", p, t0.Add(90*time.Minute))
	v, _ = rateOf(o, "svc.docker.group.restarts_1h")
	if v != 0 {
		t.Fatalf("past the window the count clears itself, got %v", v)
	}
}

func TestWindowSurvivesACounterReset(t *testing.T) {
	rateReset()
	p := protocol.Probe{Rates: []protocol.RateRule{{Name: "svc.docker.group.restarts", Out: "svc.docker.group.restarts_1h", Window: 3600}}}
	t0 := time.Unix(30000, 0)
	for i, v := range []float64{50, 55, 3, 5} {
		o := Outcome{Metrics: []protocol.MetricPoint{{Name: "svc.docker.group.restarts", Value: v}}}
		applyRates(&o, "docker", p, t0.Add(time.Duration(i)*time.Minute))
		if got, ok := rateOf(o, "svc.docker.group.restarts_1h"); ok && got < 0 {
			t.Fatalf("a restarted engine must never report a negative count, got %v", got)
		}
	}
}

func TestRatesIgnoreUndeclaredMetrics(t *testing.T) {
	rateReset()
	p := protocol.Probe{Rates: []protocol.RateRule{{Name: "svc.mysql.aborted_connects"}}}
	t0 := time.Unix(4000, 0)
	for _, v := range []float64{1, 2} {
		o := Outcome{Metrics: []protocol.MetricPoint{{Name: "svc.mysql.uptime", Value: v}}}
		applyRates(&o, "mysql", p, t0)
		if len(o.Metrics) != 1 {
			t.Fatalf("an undeclared metric must pass through untouched, got %+v", o.Metrics)
		}
		t0 = t0.Add(60 * time.Second)
	}
}
