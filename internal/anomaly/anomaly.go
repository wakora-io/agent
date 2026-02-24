package anomaly

import (
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	alpha      = 0.05
	minSamples = 18
	zThreshold = 4.0
	sustain    = 3
	adoptAfter = 30
	cooldown   = 15 * time.Minute
	seriesTTL  = 2 * time.Hour
	sweepEvery = 30 * time.Minute
)

type Anomaly struct {
	Metric   string
	Tags     map[string]string
	Value    float64
	Baseline float64
	Sigma    float64
	Z        float64
}

type state struct {
	mean     float64
	variance float64
	samples  int
	breaches int
	lastFire time.Time
	lastSeen time.Time
}

type Detector struct {
	mu        sync.Mutex
	states    map[string]*state
	lastSweep time.Time
}

func New() *Detector {
	return &Detector{states: map[string]*state{}}
}

func (d *Detector) Observe(metric string, tags map[string]string, value float64, now time.Time) *Anomaly {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sweep(now)
	key := seriesKey(metric, tags)
	s := d.states[key]
	if s == nil {
		s = &state{mean: value}
		d.states[key] = s
	}
	s.lastSeen = now

	if s.samples >= minSamples {
		sigma := math.Sqrt(s.variance)
		floor := math.Abs(s.mean) * 0.1
		if floor < 1e-9 {
			floor = 1e-9
		}
		eff := math.Max(sigma, floor)
		z := math.Abs(value-s.mean) / eff
		if z >= zThreshold {
			s.breaches++
			var fired *Anomaly
			if s.breaches == sustain && now.Sub(s.lastFire) >= cooldown {
				s.lastFire = now
				fired = &Anomaly{Metric: metric, Tags: tags, Value: value, Baseline: s.mean, Sigma: eff, Z: z}
			}
			if s.breaches >= adoptAfter {
				s.mean = value
				s.variance = 0
				s.samples = minSamples
				s.breaches = 0
			}
			return fired
		}
		s.breaches = 0
	}

	delta := value - s.mean
	s.mean += alpha * delta
	s.variance = (1 - alpha) * (s.variance + alpha*delta*delta)
	s.samples++
	return nil
}

func (d *Detector) sweep(now time.Time) {
	if now.Sub(d.lastSweep) < sweepEvery {
		return
	}
	d.lastSweep = now
	for k, s := range d.states {
		if now.Sub(s.lastSeen) > seriesTTL {
			delete(d.states, k)
		}
	}
}

func seriesKey(metric string, tags map[string]string) string {
	if len(tags) == 0 {
		return metric
	}
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(metric)
	for _, k := range keys {
		b.WriteString("|" + k + "=" + tags[k])
	}
	return b.String()
}
