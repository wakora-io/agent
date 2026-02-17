package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"strconv"
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
	connected    atomic.Bool

	mu           sync.Mutex
	facts        []discovery.Fact
	defs         []protocol.Definition
	roles        map[string]string
	active       []protocol.Definition
	lastRun      map[string]time.Time
	serviceFacts map[string]map[string]string
	probeFacts   map[string][]protocol.Fact
	tailers      map[string]*defs.Tailer
	trapL        map[int]*defs.TrapListener
	syslogL      map[int]*defs.SyslogListener
	listenerPrev map[string]listenerCounts

	lastSignal   string
	baselineTold bool
}

type listenerCounts struct {
	total, severe uint64
	matches       map[string]uint64
	at            time.Time
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
		trapL:        map[int]*defs.TrapListener{},
		syslogL:      map[int]*defs.SyslogListener{},
		listenerPrev: map[string]listenerCounts{},
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
	go a.offlineLoop(ctx, interval)
	return client.Run(ctx, func(conn transport.Conn) error {
		a.connected.Store(true)
		defer a.connected.Store(false)
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
				pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
				err := conn.Ping(pctx)
				cancel()
				if err != nil {
					log.Printf("link dead (ping failed): %v", err)
					return err
				}
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
		detail, err := anomalyDetail(an)
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

func anomalyDetail(an *anomaly.Anomaly) ([]byte, error) {
	return json.Marshal(map[string]any{
		"metric":   an.Metric,
		"tags":     an.Tags,
		"value":    round2(an.Value),
		"baseline": round2(an.Baseline),
		"sigma":    round2(an.Sigma),
		"z":        round2(an.Z),
	})
}

func (a *Agent) offlineLoop(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if a.connected.Load() {
			continue
		}
		batch := a.collect()
		if msg, err := protocol.Encode(protocol.TypeMetrics, 0, batch); err == nil {
			if raw, err := json.Marshal(msg); err == nil {
				_ = a.ring.Append(raw)
			}
		}
		now := time.Now()
		for _, p := range batch.Points {
			an := a.detector.Observe(p.Name, p.Tags, p.Value, now)
			if an == nil {
				continue
			}
			log.Printf("anomaly (offline, spooled): %s z=%.1f", an.Metric, an.Z)
			detail, err := anomalyDetail(an)
			if err != nil {
				continue
			}
			msg, err := protocol.Encode(protocol.TypeEvent, 0, protocol.AgentEvent{
				ServerID:  a.cfg.ServerID,
				Hostname:  a.cfg.Hostname,
				Kind:      "anomaly",
				Detail:    string(detail),
				Timestamp: now.Unix(),
			})
			if err != nil {
				continue
			}
			if raw, err := json.Marshal(msg); err == nil {
				_ = a.ring.Append(raw)
			}
		}
	}
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
	if a.cfg.Baseline {
		if len(a.defs) > 0 && !a.baselineTold {
			log.Printf("baseline mode: %d signed definition(s) held, probe execution withheld until opt-in", len(a.defs))
			a.baselineTold = true
		}
		a.active = nil
		return
	}
	prev := map[string]bool{}
	for _, d := range a.active {
		prev[d.Service] = true
	}
	var active []protocol.Definition
	activeSet := map[string]bool{}
	for _, d := range a.defs {
		on := false
		reason := ""
		if len(d.Hosts) > 0 {
			switch a.collectorState(d.Service, d.Hosts) {
			case collectorActive:
				on = true
				reason = "collector role"
			case collectorStandby:
				log.Printf("service %s: standby collector (active: %s)", d.Service, a.roles[d.Service])
			}
		} else if defs.Matches(d, a.facts) {
			on = true
			reason = "matched"
		}
		if on {
			active = append(active, d)
			if !prev[d.Service] && !activeSet[d.Service] {
				log.Printf("service %s: %s, %d probe(s) activated", d.Service, reason, len(d.Probes))
			}
			activeSet[d.Service] = true
		}
	}
	for svc := range prev {
		if !activeSet[svc] {
			log.Printf("service unmatched: %s, probes deactivated", svc)
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
			if p.Type == "procfact" {
				a.mu.Lock()
				facts := a.facts
				a.mu.Unlock()
				if pf := defs.ProcFacts(facts, p); len(pf) > 0 && a.mergeServiceFacts(d.Service, pf) {
					factsChanged = true
				}
				continue
			}
			if p.Type == "file" && p.Path == "" && p.PathFrom != "" {
				a.mu.Lock()
				if sf := a.serviceFacts[d.Service]; sf != nil {
					p.Path = sf[p.PathFrom]
				}
				a.mu.Unlock()
				if p.Path == "" {
					continue
				}
			}
			if p.Type == "traps" {
				if err := a.runTraps(conn, d.Service, p); err != nil {
					return err
				}
				continue
			}
			if p.Type == "syslog" {
				if err := a.runSyslog(conn, d.Service, p); err != nil {
					return err
				}
				continue
			}
			if (p.Type == "sql" || p.Type == "redis" || p.Type == "tcp") && p.Address == "" && !p.Socket && p.PortProcess != "" {
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

const (
	collectorOff = iota
	collectorStandby
	collectorActive
)

func (a *Agent) collectorState(service string, hosts []string) int {
	member := false
	for _, h := range hosts {
		if h == a.cfg.Hostname || h == a.cfg.ServerID {
			member = true
			break
		}
	}
	if !member {
		return collectorOff
	}
	if active := a.roles[service]; active != "" && active != a.cfg.Hostname && active != a.cfg.ServerID {
		return collectorStandby
	}
	return collectorActive
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

func (a *Agent) snmpTargets() map[string][]string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := map[string][]string{}
	for _, d := range a.active {
		for _, p := range d.Probes {
			if p.Type != "snmp" || p.Target == "" {
				continue
			}
			host := p.Target
			if h, _, ok := strings.Cut(p.Target, ":"); ok {
				host = h
			}
			out[host] = append(out[host], d.Service)
		}
	}
	return out
}

func (a *Agent) runTraps(conn transport.Conn, service string, p protocol.Probe) error {
	port := p.Port
	if port <= 0 {
		port = 162
	}
	l := a.trapL[port]
	if l == nil {
		l = defs.NewTrapListener(port)
		l.Start()
		a.trapL[port] = l
		log.Printf("trap listener started on udp/%d", port)
	}
	targets := a.snmpTargets()
	allowed := make([]string, 0, len(targets)+len(p.AllowFrom))
	for host := range targets {
		allowed = append(allowed, host)
	}
	allowed = append(allowed, p.AllowFrom...)
	l.SetAllowed(allowed)

	events, total, dropped, lerr := l.Drain()
	check := protocol.CheckResult{
		ServerID:  a.cfg.ServerID,
		Hostname:  a.cfg.Hostname,
		CheckID:   service + "/" + p.Name,
		Kind:      "traps",
		Target:    "udp/" + strconv.Itoa(port),
		Timestamp: time.Now().Unix(),
	}
	if lerr != nil {
		check.Status = "fail"
		check.Error = lerr.Error()
		return a.sendCheck(conn, check)
	}
	check.Status = "ok"
	if err := a.sendCheck(conn, check); err != nil {
		return err
	}

	const forwardCap = 20
	for i, ev := range events {
		if i >= forwardCap {
			log.Printf("trap forward cap reached, %d trap(s) summarized", len(events)-forwardCap)
			break
		}
		detail, err := json.Marshal(map[string]any{
			"source": ev.Source, "oid": ev.OID, "name": ev.Name, "vars": ev.Vars,
		})
		if err != nil {
			continue
		}
		a.seq++
		msg, err := protocol.Encode(protocol.TypeEvent, a.seq, protocol.AgentEvent{
			ServerID:  a.cfg.ServerID,
			Hostname:  a.cfg.Hostname,
			Kind:      "trap",
			Detail:    string(detail),
			Timestamp: ev.At.Unix(),
		})
		if err != nil {
			continue
		}
		if err := conn.Send(msg); err != nil {
			return err
		}
	}

	if len(events) > 0 {
		a.mu.Lock()
		for _, ev := range events {
			for _, svc := range targets[ev.Source] {
				delete(a.lastRun, svc)
				log.Printf("trap %s from %s: confirming poll of %s scheduled", ev.Name, ev.Source, svc)
			}
		}
		a.mu.Unlock()
	}

	pts := []protocol.MetricPoint{
		{Name: "dev.traps.received_total", Value: float64(total)},
		{Name: "dev.traps.dropped_total", Value: float64(dropped)},
	}
	return a.sendProbeMetrics(conn, pts)
}

func (a *Agent) runSyslog(conn transport.Conn, service string, p protocol.Probe) error {
	port := p.Port
	if port <= 0 {
		port = 514
	}
	l := a.syslogL[port]
	if l == nil {
		l = defs.NewSyslogListener(port)
		l.Start()
		a.syslogL[port] = l
		log.Printf("syslog listener started on udp/%d", port)
	}
	l.Configure(p.Counters, p.AllowFrom)
	total, severe, dropped, matches, lerr := l.Snapshot()
	check := protocol.CheckResult{
		ServerID:  a.cfg.ServerID,
		Hostname:  a.cfg.Hostname,
		CheckID:   service + "/" + p.Name,
		Kind:      "syslog",
		Target:    "udp/" + strconv.Itoa(port),
		Timestamp: time.Now().Unix(),
	}
	if lerr != nil {
		check.Status = "fail"
		check.Error = lerr.Error()
		return a.sendCheck(conn, check)
	}
	check.Status = "ok"
	if err := a.sendCheck(conn, check); err != nil {
		return err
	}

	key := service + "/" + p.Name
	now := time.Now()
	prev, had := a.listenerPrev[key]
	a.listenerPrev[key] = listenerCounts{total: total, severe: severe, matches: matches, at: now}
	pts := []protocol.MetricPoint{
		{Name: "dev.syslog.dropped_total", Value: float64(dropped)},
	}
	if had {
		secs := now.Sub(prev.at).Seconds()
		if secs > 0 {
			pts = append(pts,
				protocol.MetricPoint{Name: "dev.syslog.rate", Value: rate(total, prev.total, secs)},
				protocol.MetricPoint{Name: "dev.syslog.severe_rate", Value: rate(severe, prev.severe, secs)},
			)
			for name, v := range matches {
				pts = append(pts, protocol.MetricPoint{Name: name, Value: rate(v, prev.matches[name], secs)})
			}
		}
	}
	return a.sendProbeMetrics(conn, pts)
}

func rate(cur, prev uint64, secs float64) float64 {
	if cur < prev {
		prev = 0
	}
	return float64(int(float64(cur-prev)/secs*1000+0.5)) / 1000
}

func (a *Agent) sendProbeMetrics(conn transport.Conn, pts []protocol.MetricPoint) error {
	if len(pts) == 0 {
		return nil
	}
	a.seq++
	msg, err := protocol.Encode(protocol.TypeMetrics, a.seq, protocol.MetricsBatch{
		ServerID:  a.cfg.ServerID,
		Hostname:  a.cfg.Hostname,
		Timestamp: time.Now().Unix(),
		Points:    pts,
	})
	if err != nil {
		return nil
	}
	if err := conn.Send(msg); err != nil {
		return err
	}
	return a.observePoints(conn, pts)
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
		a.roles = set.Roles
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
