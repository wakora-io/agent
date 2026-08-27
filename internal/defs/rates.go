package defs

import (
	"sort"
	"strings"
	"sync"
	"time"

	"wakora.io/agent/internal/protocol"
)

const rateStale = 30 * time.Minute

type rateMark struct {
	value float64
	at    time.Time
}

var (
	rateMu   sync.Mutex
	rateSeen = map[string]rateMark{}
	rateHist = map[string][]rateMark{}

	lastMu   sync.Mutex
	lastSeen = map[string]rateMark{}
)

const rateHistCap = 240

func windowDelta(key string, value float64, now time.Time, window time.Duration) (float64, bool) {
	h := rateHist[key]
	if n := len(h); n > 0 && value < h[n-1].value {
		h = nil
	}
	h = append(h, rateMark{value: value, at: now})
	cut := now.Add(-window)
	drop := 0
	for drop+1 < len(h) && h[drop+1].at.Before(cut) {
		drop++
	}
	h = h[drop:]
	if len(h) > rateHistCap {
		h = h[len(h)-rateHistCap:]
	}
	rateHist[key] = h
	if len(h) < 2 {
		return 0, false
	}
	return value - h[0].value, true
}

func RememberMetrics(service string, pts []protocol.MetricPoint, now time.Time) {
	if len(pts) == 0 {
		return
	}
	lastMu.Lock()
	defer lastMu.Unlock()
	for k, m := range lastSeen {
		if now.Sub(m.at) > rateStale {
			delete(lastSeen, k)
		}
	}
	for _, pt := range pts {
		lastSeen[rateKey(service, pt.Name, pt.Tags)] = rateMark{value: pt.Value, at: now}
	}
}

func Derived(service string, rules []protocol.DerivedRule, now time.Time) []protocol.MetricPoint {
	if len(rules) == 0 {
		return nil
	}
	lastMu.Lock()
	defer lastMu.Unlock()
	var out []protocol.MetricPoint
	for _, r := range rules {
		if strings.TrimSpace(r.Name) == "" {
			continue
		}
		num, okN := lastSeen[rateKey(service, r.Num, nil)]
		den, okD := lastSeen[rateKey(service, r.Den, nil)]
		if !okN || !okD || den.value <= 0 {
			continue
		}
		if now.Sub(num.at) > rateStale || now.Sub(den.at) > rateStale {
			continue
		}
		scale := r.Scale
		if scale == 0 {
			scale = 1
		}
		out = append(out, protocol.MetricPoint{Name: r.Name, Value: num.value / den.value * scale})
	}
	return out
}

func rateKey(service, name string, tags map[string]string) string {
	var b strings.Builder
	b.WriteString(service)
	b.WriteString("|")
	b.WriteString(name)
	if len(tags) == 0 {
		return b.String()
	}
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString("|")
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(tags[k])
	}
	return b.String()
}

func ratePer(per string) (float64, string) {
	switch strings.ToLower(strings.TrimSpace(per)) {
	case "min", "minute":
		return 60, "_per_min"
	case "hour", "h":
		return 3600, "_per_hour"
	default:
		return 1, "_rate"
	}
}

func applyRates(o *Outcome, service string, p protocol.Probe, now time.Time) {
	if len(p.Rates) == 0 || len(o.Metrics) == 0 {
		return
	}
	wanted := make(map[string][]protocol.RateRule, len(p.Rates))
	for _, r := range p.Rates {
		if strings.TrimSpace(r.Name) == "" {
			continue
		}
		wanted[r.Name] = append(wanted[r.Name], r)
	}
	if len(wanted) == 0 {
		return
	}
	rateMu.Lock()
	defer rateMu.Unlock()
	for k, m := range rateSeen {
		if now.Sub(m.at) > rateStale {
			delete(rateSeen, k)
		}
	}
	for k, h := range rateHist {
		if len(h) == 0 || now.Sub(h[len(h)-1].at) > rateStale {
			delete(rateHist, k)
		}
	}
	var out []protocol.MetricPoint
	for _, pt := range o.Metrics {
		rules := wanted[pt.Name]
		if len(rules) == 0 {
			continue
		}
		key := rateKey(service, pt.Name, pt.Tags)
		prev, seen := rateSeen[key]
		rateSeen[key] = rateMark{value: pt.Value, at: now}
		for _, r := range rules {
			name := strings.TrimSpace(r.Out)
			if r.Window > 0 {
				if name == "" {
					name = pt.Name + "_window"
				}
				if d, ok := windowDelta(key+"|"+name, pt.Value, now, time.Duration(r.Window)*time.Second); ok {
					out = append(out, protocol.MetricPoint{Name: name, Value: d, Tags: pt.Tags})
				}
				continue
			}
			if !seen {
				continue
			}
			elapsed := now.Sub(prev.at).Seconds()
			if elapsed <= 0 || pt.Value < prev.value {
				continue
			}
			mult, suffix := ratePer(r.Per)
			if name == "" {
				name = pt.Name + suffix
			}
			out = append(out, protocol.MetricPoint{Name: name, Value: (pt.Value - prev.value) / elapsed * mult, Tags: pt.Tags})
		}
	}
	o.Metrics = append(o.Metrics, out...)
}
