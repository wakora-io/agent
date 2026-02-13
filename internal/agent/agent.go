package agent

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"wakora.io/agent/internal/buffer"
	"wakora.io/agent/internal/buildinfo"
	"wakora.io/agent/internal/config"
	"wakora.io/agent/internal/defs"
	"wakora.io/agent/internal/discovery"
	"wakora.io/agent/internal/metrics"
	"wakora.io/agent/internal/protocol"
	"wakora.io/agent/internal/transport"
)

type Agent struct {
	cfg          *config.Config
	ring         *buffer.Ring
	publisherKey string
	metrics      *metrics.Collector
	key          atomic.Value
	seq          uint64

	mu           sync.Mutex
	facts        []discovery.Fact
	defs         []protocol.Definition
	active       []protocol.Definition
	lastRun      map[string]time.Time
	serviceFacts map[string]map[string]string

	lastSignal string
}

func New(cfg *config.Config, ring *buffer.Ring, publisherKey string) *Agent {
	a := &Agent{
		cfg:          cfg,
		ring:         ring,
		publisherKey: publisherKey,
		metrics:      metrics.NewCollector(),
		lastRun:      map[string]time.Time{},
		serviceFacts: map[string]map[string]string{},
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
	a.seq++
	msg, err := protocol.Encode(protocol.TypeMetrics, a.seq, a.collect())
	if err != nil {
		return nil
	}
	if err := conn.Send(msg); err != nil {
		if raw, e := json.Marshal(msg); e == nil {
			_ = a.ring.Append(raw)
		}
		return err
	}
	return nil
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
			o := defs.RunProbe(d.Service, p)
			o.Check.ServerID = a.cfg.ServerID
			o.Check.Hostname = a.cfg.Hostname
			a.seq++
			msg, err := protocol.Encode(protocol.TypeCheck, a.seq, o.Check)
			if err != nil {
				continue
			}
			if err := conn.Send(msg); err != nil {
				return err
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
			}
			if len(o.Facts) > 0 && a.mergeServiceFacts(d.Service, o.Facts) {
				factsChanged = true
			}
		}
	}
	if factsChanged {
		return a.sendDiscovery(conn)
	}
	return nil
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
