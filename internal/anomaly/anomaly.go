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

type Class struct {
	Match    string  `json:"match"`
	MinDelta float64 `json:"minDelta"`
	UpOnly   bool    `json:"upOnly,omitempty"`
}

type Config struct {
	Z       float64  `json:"z,omitempty"`
	Sustain int      `json:"sustain,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
	Classes []Class  `json:"classes,omitempty"`
}

func DefaultConfig() Config {
	return Config{
		Z:       zThreshold,
		Sustain: sustain,
		Exclude: []string{
			"host.top.%",
			"%.max_ms",
			"host.load1",
			"host.load5",
			"host.load15",
			"%uptime%",
			"svc.apm-profile.%",
		},
		Classes: []Class{
			{Match: "host.load%per_core", MinDelta: 0.5, UpOnly: true},
			{Match: "%error%", MinDelta: 1, UpOnly: true},
			{Match: "%fail%", MinDelta: 1, UpOnly: true},
			{Match: "%_pct", MinDelta: 10, UpOnly: true},
			{Match: "%_ms", MinDelta: 100, UpOnly: true},
			{Match: "%_us", MinDelta: 100000, UpOnly: true},
			{Match: "%bytes%", MinDelta: 1 << 20},
			{Match: "%io_bps", MinDelta: 1 << 20},
			{Match: "%_rate", MinDelta: 1},
			{Match: "%per_sec", MinDelta: 1},
			{Match: "%per_min", MinDelta: 5},
			{Match: "%", MinDelta: 5},
		},
	}
}

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
	cfg       Config
}

func New() *Detector {
	return &Detector{states: map[string]*state{}, cfg: DefaultConfig()}
}

func (d *Detector) SetConfig(c Config) {
	def := DefaultConfig()
	if c.Z <= 0 {
		c.Z = def.Z
	}
	if c.Sustain < 1 {
		c.Sustain = def.Sustain
	}
	if len(c.Exclude) == 0 {
		c.Exclude = def.Exclude
	}
	if len(c.Classes) == 0 {
		c.Classes = def.Classes
	}
	d.mu.Lock()
	d.cfg = c
	d.mu.Unlock()
}

func (d *Detector) Observe(metric string, tags map[string]string, value float64, now time.Time) *Anomaly {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sweep(now)
	for _, p := range d.cfg.Exclude {
		if like(p, metric) {
			return nil
		}
	}
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
		if z >= d.cfg.Z && d.meaningful(metric, value, s.mean) {
			s.breaches++
			var fired *Anomaly
			if s.breaches == d.cfg.Sustain && now.Sub(s.lastFire) >= cooldown {
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

func (d *Detector) meaningful(metric string, value, mean float64) bool {
	for _, c := range d.cfg.Classes {
		if !like(c.Match, metric) {
			continue
		}
		if c.UpOnly && value <= mean {
			return false
		}
		return math.Abs(value-mean) >= c.MinDelta
	}
	return true
}

func like(pattern, s string) bool {
	parts := strings.Split(pattern, "%")
	if len(parts) == 1 {
		return pattern == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for _, p := range parts[1 : len(parts)-1] {
		i := strings.Index(s, p)
		if i < 0 {
			return false
		}
		s = s[i+len(p):]
	}
	return strings.HasSuffix(s, parts[len(parts)-1])
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
