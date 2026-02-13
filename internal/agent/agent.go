package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"wakora.io/agent/internal/anomaly"
	"wakora.io/agent/internal/buffer"
	"wakora.io/agent/internal/buildinfo"
	"wakora.io/agent/internal/config"
	"wakora.io/agent/internal/defs"
	"wakora.io/agent/internal/discovery"
	"wakora.io/agent/internal/metrics"
	"wakora.io/agent/internal/protocol"
	"wakora.io/agent/internal/secret"
	"wakora.io/agent/internal/transport"
)

type Agent struct {
	cfg          *config.Config
	ring         *buffer.Ring
	publisherKey string
	metrics      *metrics.Collector
	detector     *anomaly.Detector
	key          atomic.Value
	seq          uint64

	mu           sync.Mutex
	facts        []discovery.Fact
	defs         []protocol.Definition
	active       []protocol.Definition
	lastRun      map[string]time.Time
	serviceFacts map[string]map[string]string
	probeFacts   map[string][]protocol.Fact
	tailers      map[string]*defs.Tailer

	lastSignal string
}

func New(cfg *config.Config, ring *buffer.Ring, publisherKey string) *Agent {
	a := &Agent{
		cfg:          cfg,
		ring:         ring,
		publisherKey: publisherKey,
		metrics:      metrics.NewCollector(),
		detector:     anomaly.New(),
		lastRun:      map[string]time.Time{},
		serviceFacts: map[string]map[string]string{},
		probeFacts:   map[string][]protocol.Fact{},
		tailers:      map[string]*defs.Tailer{},
	}
	a.key.Store(cfg.Key)
	return a
}

func (a *Agent) Key() string {
	v, _ := a.key.Load().(string)
	return v
}

func (a *Agent) collect() protocol.MetricsBatch {
	ts, pts := a.metrics.Collect()
	points := make([]protocol.MetricPoint, len(pts))
	for i, p := range pts {
		points[i] = protocol.MetricPoint{Name: p.Name, Value: p.Value, Tags: p.Tags}
	}
	return protocol.MetricsBatch{
		ServerID:  a.cfg.ServerID,
		Hostname:  a.cfg.Hostname,
		Timestamp: ts,
		Points:    points,
	}
}

func (a *Agent) Run(ctx context.Context, client *transport.Client, interval, heartbeatEvery, discoveryEvery, discoveryCheck time.Duration) error {
	return client.Run(ctx, func(conn transport.Conn) error {
		a.drainSpool(conn)
		if err := a.sendHeartbeat(conn); err != nil {
			return err
		}
		if err := a.sendMetrics(conn); err != nil {
			return err
		}
		if err := a.sendDiscovery(conn); err != nil {
			return err
		}

		kick := make(chan struct{}, 1)
		dkick := make(chan struct{}, 1)
		readErr := make(chan error, 1)
		go func() {
			for {
				m, err := conn.Recv()
				if err != nil {
					readErr <- err
					return
				}
				a.handleDownstream(m, kick, dkick)
			}
		}()

		mt := time.NewTicker(interval)
		defer mt.Stop()
		hb := time.NewTicker(heartbeatEvery)
		defer hb.Stop()
		dt := time.NewTicker(discoveryEvery)
		defer dt.Stop()
		dc := time.NewTicker(discoveryCheck)
		defer dc.Stop()
		pt := time.NewTicker(15 * time.Second)
		defer pt.Stop()
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case err := <-readErr:
				return err
			case <-kick:
				if err := a.sendMetrics(conn); err != nil {
					return err
				}
			case <-dkick:
				if err := a.sendDiscovery(conn); err != nil {
					return err
				}
			case <-hb.C:
				if err := a.sendHeartbeat(conn); err != nil {
					return err
				}
			case <-mt.C:
				if err := a.sendMetrics(conn); err != nil {
					return err
				}
			case <-dt.C:
				if err := a.sendDiscovery(conn); err != nil {
					return err
				}
			case <-dc.C:
				if s := discovery.ChangeSignal(); s != a.lastSignal {
					log.Print("host change detected, refreshing discovery")
					if err := a.sendDiscovery(conn); err != nil {
						return err
					}
				}
			case <-pt.C:
				if err := a.runDueProbes(conn); err != nil {
					return err
				}
			}
		}
	})
}

func (a *Agent) sendMetrics(conn transport.Conn) error {
	batch := a.collect()
	a.seq++
	msg, err := protocol.Encode(protocol.TypeMetrics, a.seq, batch)
	if err != nil {
		return nil
	}
	if err := conn.Send(msg); err != nil {
		if raw, e := json.Marshal(msg); e == nil {
			_ = a.ring.Append(raw)
		}
		return err
	}
	return a.observePoints(conn, batch.Points)
}

func (a *Agent) observePoints(conn transport.Conn, points []protocol.MetricPoint) error {
	now := time.Now()
	for _, p := range points {
		an := a.detector.Observe(p.Name, p.Tags, p.Value, now)
		if an == nil {
			continue
		}
		log.Printf("anomaly: %s z=%.1f value=%.2f baseline=%.2f", an.Metric, an.Z, an.Value, an.Baseline)
		detail, err := json.Marshal(map[string]any{
			"metric":   an.Metric,
			"tags":     an.Tags,
			"value":    round2(an.Value),
			"baseline": round2(an.Baseline),
			"sigma":    round2(an.Sigma),
			"z":        round2(an.Z),
		})
		if err != nil {
			continue
		}
		a.seq++
		msg, err := protocol.Encode(protocol.TypeEvent, a.seq, protocol.AgentEvent{
			ServerID:  a.cfg.ServerID,
			Hostname:  a.cfg.Hostname,
			Kind:      "anomaly",
			Detail:    string(detail),
			Timestamp: now.Unix(),
		})
		if err != nil {
			continue
		}
		if err := conn.Send(msg); err != nil {
			return err
		}
	}
	return nil
}

func round2(v float64) float64 {
	return float64(int(v*100+0.5)) / 100
}

func (a *Agent) sendHeartbeat(conn transport.Conn) error {
	a.seq++
	msg, err := protocol.Encode(protocol.TypeHeartbeat, a.seq, protocol.Heartbeat{
		ServerID:  a.cfg.ServerID,
		Hostname:  a.cfg.Hostname,
		Version:   buildinfo.Version,
		Timestamp: time.Now().Unix(),
	})
	if err != nil {
		return nil
	}
	return conn.Send(msg)
}

func (a *Agent) sendDiscovery(conn transport.Conn) error {
	facts := discovery.Collect()
	a.lastSignal = discovery.ChangeSignal()
	a.mu.Lock()
	a.facts = facts
	a.mu.Unlock()
	a.refreshActive()

	pf := make([]protocol.Fact, len(facts))
	for i, f := range facts {
		pf[i] = protocol.Fact{Kind: f.Kind, Key: f.Key, Payload: f.Payload}
	}
	a.mu.Lock()
	for svc, kv := range a.serviceFacts {
		if payload, err := json.Marshal(kv); err == nil {
			pf = append(pf, protocol.Fact{Kind: "service", Key: svc, Payload: string(payload)})
		}
	}
	for _, extra := range a.probeFacts {
		pf = append(pf, extra...)
	}
	a.mu.Unlock()
	a.seq++
	msg, err := protocol.Encode(protocol.TypeDiscovery, a.seq, protocol.DiscoverySnapshot{
		ServerID:  a.cfg.ServerID,
		Hostname:  a.cfg.Hostname,
		Timestamp: time.Now().Unix(),
		Facts:     pf,
	})
	if err != nil {
		return nil
	}
	return conn.Send(msg)
}

func (a *Agent) refreshActive() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.facts == nil {
		return
	}
	prev := map[string]bool{}
	for _, d := range a.active {
		prev[d.Service] = true
	}
	var active []protocol.Definition
	activeSet := map[string]bool{}
	for _, d := range a.defs {
		if defs.Matches(d, a.facts) {
			active = append(active, d)
			activeSet[d.Service] = true
			if !prev[d.Service] {
				log.Printf("service matched: %s, %d probe(s) activated", d.Service, len(d.Probes))
			}
		} else if prev[d.Service] {
			log.Printf("service unmatched: %s, probes deactivated", d.Service)
		}
	}
	for svc := range a.serviceFacts {
		if !activeSet[svc] {
			delete(a.serviceFacts, svc)
		}
	}
	for key := range a.probeFacts {
		svc, _, _ := strings.Cut(key, "/")
		if !activeSet[svc] {
			delete(a.probeFacts, key)
		}
	}
	a.active = active
}

func (a *Agent) runDueProbes(conn transport.Conn) error {
	a.mu.Lock()
	var due []protocol.Definition
	now := time.Now()
	for _, d := range a.active {
		interval := time.Duration(d.IntervalSec) * time.Second
		if interval <= 0 {
			interval = time.Minute
		}
		if now.Sub(a.lastRun[d.Service]) >= interval {
			a.lastRun[d.Service] = now
			due = append(due, d)
		}
	}
	a.mu.Unlock()

	factsChanged := false
	for _, d := range due {
		for _, p := range d.Probes {
			if p.Type == "logtail" {
				if err := a.runLogtail(conn, d.Service, p); err != nil {
					return err
				}
				continue
			}
			if (p.Type == "sql" || p.Type == "redis") && p.Address == "" && !p.Socket && p.PortProcess != "" {
				if port := a.resolvePort(p.PortProcess); port != "" {
					p.Address = "127.0.0.1:" + port
				}
			}
			o := defs.RunProbeWithSecrets(d.Service, p, a.resolveSecret)
			for _, check := range append([]protocol.CheckResult{o.Check}, o.Extra...) {
				check.ServerID = a.cfg.ServerID
				check.Hostname = a.cfg.Hostname
				a.seq++
				msg, err := protocol.Encode(protocol.TypeCheck, a.seq, check)
				if err != nil {
					continue
				}
				if err := conn.Send(msg); err != nil {
					return err
				}
			}
			if len(o.Metrics) > 0 {
				a.seq++
				mmsg, err := protocol.Encode(protocol.TypeMetrics, a.seq, protocol.MetricsBatch{
					ServerID:  a.cfg.ServerID,
					Hostname:  a.cfg.Hostname,
					Timestamp: o.Check.Timestamp,
					Points:    o.Metrics,
				})
				if err == nil {
					if err := conn.Send(mmsg); err != nil {
						return err
					}
				}
				if err := a.observePoints(conn, o.Metrics); err != nil {
					return err
				}
			}
			if len(o.Facts) > 0 && a.mergeServiceFacts(d.Service, o.Facts) {
				factsChanged = true
			}
			if a.setProbeFacts(d.Service+"/"+p.Name, o.InvFacts) {
				factsChanged = true
			}
		}
	}
	if factsChanged {
		return a.sendDiscovery(conn)
	}
	return nil
}

func (a *Agent) setProbeFacts(key string, facts []protocol.Fact) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(facts) == 0 {
		if _, had := a.probeFacts[key]; had {
			delete(a.probeFacts, key)
			return true
		}
		return false
	}
	newRaw, err := json.Marshal(facts)
	if err != nil {
		return false
	}
	oldRaw, _ := json.Marshal(a.probeFacts[key])
	a.probeFacts[key] = facts
	return !bytes.Equal(newRaw, oldRaw)
}

func (a *Agent) resolveSecret(name string) (secret.Cred, bool) {
	return secret.GetCred(a.cfg.Dir(), name)
}

func (a *Agent) resolvePort(process string) string {
	a.mu.Lock()
	facts := a.facts
	a.mu.Unlock()
	for _, f := range facts {
		if f.Kind != "port" {
			continue
		}
		var info struct {
			Process string `json:"process"`
		}
		if json.Unmarshal([]byte(f.Payload), &info) != nil || info.Process != process {
			continue
		}
		if i := strings.IndexByte(f.Key, '/'); i > 0 {
			return f.Key[:i]
		}
	}
	return ""
}

func (a *Agent) runLogtail(conn transport.Conn, service string, p protocol.Probe) error {
	var paths []string
	if p.Path != "" {
		paths = []string{p.Path}
	} else if p.PathFrom != "" {
		a.mu.Lock()
		if facts := a.serviceFacts[service]; facts != nil {
			for _, v := range strings.Split(facts[p.PathFrom], ",") {
				if v = strings.TrimSpace(v); v != "" {
					paths = append(paths, v)
				}
			}
		}
		a.mu.Unlock()
	}
	check := protocol.CheckResult{
		ServerID:  a.cfg.ServerID,
		Hostname:  a.cfg.Hostname,
		CheckID:   service + "/" + p.Name,
		Kind:      "logtail",
		Target:    strings.Join(paths, ","),
		Timestamp: time.Now().Unix(),
	}
	if len(paths) == 0 {
		check.Status = "fail"
		check.Error = "log path unknown (not discovered yet)"
		return a.sendCheck(conn, check)
	}

	key := service + "/" + p.Name
	t := a.tailers[key]
	if t == nil || t.Key() != strings.Join(paths, ",") {
		t = defs.NewTailer(paths)
		a.tailers[key] = t
	}
	pts, err := t.Sample(p.Counters, time.Now())
	if err != nil {
		check.Status = "fail"
		check.Error = err.Error()
		return a.sendCheck(conn, check)
	}
	check.Status = "ok"
	if err := a.sendCheck(conn, check); err != nil {
		return err
	}
	if len(pts) > 0 {
		a.seq++
		msg, err := protocol.Encode(protocol.TypeMetrics, a.seq, protocol.MetricsBatch{
			ServerID:  a.cfg.ServerID,
			Hostname:  a.cfg.Hostname,
			Timestamp: time.Now().Unix(),
			Points:    pts,
		})
		if err == nil {
			if err := conn.Send(msg); err != nil {
				return err
			}
			return a.observePoints(conn, pts)
		}
	}
	return nil
}

func (a *Agent) sendCheck(conn transport.Conn, check protocol.CheckResult) error {
	a.seq++
	msg, err := protocol.Encode(protocol.TypeCheck, a.seq, check)
	if err != nil {
		return nil
	}
	return conn.Send(msg)
}

func (a *Agent) mergeServiceFacts(service string, facts map[string]string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	cur := a.serviceFacts[service]
	if cur == nil {
		cur = map[string]string{}
		a.serviceFacts[service] = cur
	}
	changed := false
	for k, v := range facts {
		if cur[k] != v {
			cur[k] = v
			changed = true
		}
	}
	return changed
}

func (a *Agent) handleDownstream(m protocol.Message, kick, dkick chan struct{}) {
	switch m.Type {
	case protocol.TypeConfig:
		var set protocol.DefinitionSet
		if err := json.Unmarshal(m.Payload, &set); err != nil {
			return
		}
		verified := defs.Verify(set, a.publisherKey)
		a.mu.Lock()
		a.defs = verified
		a.mu.Unlock()
		log.Printf("definitions received: %d verified of %d", len(verified), len(set.Definitions))
		a.refreshActive()
	case protocol.TypeCommand:
		var c protocol.Command
		if err := json.Unmarshal(m.Payload, &c); err != nil {
			return
		}
		switch c.Action {
		case "collectNow":
			select {
			case kick <- struct{}{}:
			default:
			}
		case "discoverNow":
			select {
			case dkick <- struct{}{}:
			default:
			}
		case "rotateKey":
			if c.Key == "" {
				return
			}
			if err := a.cfg.SaveKey(c.Key); err != nil {
				log.Printf("key rotation failed: %v", err)
				return
			}
			a.key.Store(c.Key)
			log.Print("per-server key rotated")
		}
	}
}

func (a *Agent) drainSpool(conn transport.Conn) {
	_ = a.ring.Drain(func(line []byte) error {
		var m protocol.Message
		if err := json.Unmarshal(line, &m); err != nil {
			return nil
		}
		return conn.Send(m)
	})
}

func (a *Agent) DryRun() {
	b := a.collect()
	for _, p := range b.Points {
		log.Printf("metric %s=%v", p.Name, p.Value)
	}
	facts := discovery.Collect()
	for kind, n := range discovery.CountByKind(facts) {
		log.Printf("discovery: %s=%d", kind, n)
	}
}
