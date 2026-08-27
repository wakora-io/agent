package defs

import (
	"sync"
	"time"

	"wakora.io/agent/internal/protocol"
)

const (
	snmpUp        = 1
	linkMemoryCap = 4096
	linkMemoryTTL = 24 * time.Hour
)

type linkMark struct {
	carried bool
	at      time.Time
}

var (
	linkMu   sync.Mutex
	linkSeen = map[string]linkMark{}
)

func linkReset() {
	linkMu.Lock()
	linkSeen = map[string]linkMark{}
	linkMu.Unlock()
}

func linkIndexOf(tags map[string]string) string {
	if tags == nil {
		return ""
	}
	if v := tags["index"]; v != "" {
		return v
	}
	return tags["port"]
}

func applyLinkState(o *Outcome, p protocol.Probe, target string, now time.Time) {
	ls := p.LinkState
	if ls == nil || ls.Oper == "" || ls.Out == "" || len(o.Metrics) == 0 {
		return
	}
	admin := map[string]float64{}
	if ls.Admin != "" {
		for _, m := range o.Metrics {
			if m.Name == ls.Admin {
				admin[linkIndexOf(m.Tags)] = m.Value
			}
		}
	}

	linkMu.Lock()
	defer linkMu.Unlock()
	if len(linkSeen) > linkMemoryCap {
		linkSeen = map[string]linkMark{}
	}

	var out []protocol.MetricPoint
	for _, m := range o.Metrics {
		if m.Name != ls.Oper {
			continue
		}
		idx := linkIndexOf(m.Tags)
		if idx == "" {
			continue
		}
		key := target + "|" + idx
		mark := linkSeen[key]
		if !mark.at.IsZero() && now.Sub(mark.at) > linkMemoryTTL {
			mark.carried = false
		}

		lost := 0.0
		if m.Value == snmpUp {
			mark.carried = true
		} else if mark.carried {
			if a, ok := admin[idx]; !ok || a == snmpUp {
				lost = 1
			} else {
				mark.carried = false
			}
		}
		mark.at = now
		linkSeen[key] = mark

		out = append(out, protocol.MetricPoint{Name: ls.Out, Value: lost, Tags: copyTags(m.Tags)})
	}
	o.Metrics = append(o.Metrics, out...)
}
