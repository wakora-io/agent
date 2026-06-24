package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"wakora.io/agent/internal/anomaly"
	"wakora.io/agent/internal/apm"
	"wakora.io/agent/internal/buffer"
	"wakora.io/agent/internal/buildinfo"
	"wakora.io/agent/internal/config"
	"wakora.io/agent/internal/defs"
	"wakora.io/agent/internal/discovery"
	"wakora.io/agent/internal/metrics"
	"wakora.io/agent/internal/protocol"
	"wakora.io/agent/internal/secret"
	"wakora.io/agent/internal/transport"
	"wakora.io/agent/internal/update"
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
	deny         map[string]bool
	denySvc      map[string]bool
	logDeep      map[string]bool
	active       []protocol.Definition
	lastRun      map[string]time.Time
	serviceFacts map[string]map[string]string
	probeFacts   map[string][]protocol.Fact
	tailers      map[string]*defs.Tailer
	journals     map[string]*defs.JournalTailer
	logTailers   map[string]*defs.LogTailer
	dropTailFDs  atomic.Bool
	lastTailSig  uint64
	haveTailSig  bool
	logBudget    int
	logBudgetAt  time.Time
	logCapped    bool
	trapL        map[int]*defs.TrapListener
	syslogL      map[int]*defs.SyslogListener
	listenerPrev map[string]listenerCounts
	apmEngine    *apm.Engine
	apmErr       error
	apmWant      map[string]apmWantSet
	apmCurPorts  []int
	apmCurDown   map[string][]int
	apmPass      uint64
	apmDrainPass uint64

	lastSignal        string
	baselineTold      bool
	warnedUnsupported map[string]bool
	custom            chan []protocol.MetricPoint
	spans             chan []protocol.Span
	rum               chan []protocol.RumItem
	rumAllowed        atomic.Value
	profiles          chan defs.Outcome
	profiling         map[string]bool
	vhostDone         chan probeDone
	vhostBusy         map[string]bool
	updateKick        chan struct{}
	updateNote        chan [2]string
	updateNoteDone    chan struct{}
	otlpAuto          atomic.Bool

	pmu          sync.Mutex
	pending      map[uint64][]byte
	pendingFreed chan struct{}

	pin         atomic.Value
	pinFromPush atomic.Bool

	lastAck     atomic.Int64
	lastConnect atomic.Int64
	lastRotate  atomic.Int64
	lastError   atomic.Value
}

var pendingCap = 8192
var pendingStallTimeout = 30 * time.Second

var errPendingStalled = errors.New("pending buffer full: gateway not acknowledging")

var probeTick = 15 * time.Second

func (a *Agent) SetUpdateKick(ch chan struct{}) { a.updateKick = ch }

func (a *Agent) AnnounceUpdate(from, to string) {
	if a.updateNote == nil {
		return
	}
	select {
	case a.updateNote <- [2]string{from, to}:
	default:
		return
	}
	select {
	case <-a.updateNoteDone:
	case <-time.After(3 * time.Second):
	}
}

type trackedConn struct {
	inner transport.Conn
	a     *Agent
}

func (t *trackedConn) Send(m protocol.Message) error {
	if m.Seq != 0 {
		raw, err := t.a.trackPending(m)
		if err != nil {
			if raw != nil {
				_ = t.a.ring.Append(raw)
			}
			return err
		}
	}
	return t.inner.Send(m)
}
func (t *trackedConn) Recv() (protocol.Message, error) { return t.inner.Recv() }
func (t *trackedConn) Ping(ctx context.Context) error  { return t.inner.Ping(ctx) }
func (t *trackedConn) Close() error                    { return t.inner.Close() }

func (a *Agent) trackPending(m protocol.Message) ([]byte, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, nil
	}
	a.pmu.Lock()
	deadline := time.Now().Add(pendingStallTimeout)
	for len(a.pending) >= pendingCap {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			a.pmu.Unlock()
			return raw, errPendingStalled
		}
		a.pmu.Unlock()
		wait := remaining
		if wait > 100*time.Millisecond {
			wait = 100 * time.Millisecond
		}
		select {
		case <-a.pendingFreed:
		case <-time.After(wait):
		}
		a.pmu.Lock()
	}
	a.pending[m.Seq] = raw
	a.pmu.Unlock()
	return raw, nil
}

func (a *Agent) ackPending(seq uint64) {
	a.pmu.Lock()
	delete(a.pending, seq)
	a.pmu.Unlock()
	select {
	case a.pendingFreed <- struct{}{}:
	default:
	}
}

func (a *Agent) spoolPending() {
	a.pmu.Lock()
	pend := a.pending
	a.pending = map[uint64][]byte{}
	a.pmu.Unlock()
	n := 0
	for _, raw := range pend {
		if a.ring.Append(raw) == nil {
			n++
		}
	}
	if n > 0 {
		log.Printf("connection lost: %d unacked message(s) spooled for replay", n)
	}
}

type listenerCounts struct {
	total, severe uint64
	matches       map[string]uint64
	at            time.Time
}

func New(cfg *config.Config, ring *buffer.Ring, publisherKey string) *Agent {
	a := &Agent{
		cfg:               cfg,
		ring:              ring,
		publisherKey:      publisherKey,
		metrics:           metrics.NewCollector(),
		detector:          anomaly.New(),
		lastRun:           map[string]time.Time{},
		serviceFacts:      map[string]map[string]string{},
		probeFacts:        map[string][]protocol.Fact{},
		tailers:           map[string]*defs.Tailer{},
		journals:          map[string]*defs.JournalTailer{},
		logTailers:        map[string]*defs.LogTailer{},
		trapL:             map[int]*defs.TrapListener{},
		syslogL:           map[int]*defs.SyslogListener{},
		listenerPrev:      map[string]listenerCounts{},
		warnedUnsupported: map[string]bool{},
		custom:            make(chan []protocol.MetricPoint, 256),
		spans:             make(chan []protocol.Span, 64),
		rum:               make(chan []protocol.RumItem, 256),
		profiles:          make(chan defs.Outcome, 8),
		profiling:         map[string]bool{},
		vhostDone:         make(chan probeDone, 8),
		vhostBusy:         map[string]bool{},
		updateNote:        make(chan [2]string, 1),
		updateNoteDone:    make(chan struct{}, 1),
		pending:           map[uint64][]byte{},
		pendingFreed:      make(chan struct{}, 1),
	}
	a.key.Store(cfg.Key)
	a.pin.Store(cfg.Pin)
	return a
}

func (a *Agent) Key() string {
	v, _ := a.key.Load().(string)
	return v
}

func (a *Agent) EffectivePin() string {
	v, _ := a.pin.Load().(string)
	return v
}

func (a *Agent) kickUpdate() {
	if a.updateKick != nil {
		select {
		case a.updateKick <- struct{}{}:
		default:
		}
	}
}

func (a *Agent) applyPushedPin(p string) {
	cur := a.EffectivePin()
	if p == "" {
		if !a.pinFromPush.Load() || cur == "" {
			return
		}
		a.pin.Store("")
		a.pinFromPush.Store(false)
		_ = config.WriteOverride(a.cfg.Dir(), "agent", "pin", "")
		a.kickUpdate()
		return
	}
	if !update.PinSupported(p) {
		log.Printf("ignoring pushed pin %s: below the pin-aware floor r%d", p, update.PinFloor)
		return
	}
	a.pinFromPush.Store(true)
	if p == cur {
		return
	}
	a.pin.Store(p)
	_ = config.WriteOverride(a.cfg.Dir(), "agent", "pin", p)
	a.kickUpdate()
}

func (a *Agent) RefreshIdentity() {
	a.key.Store(a.cfg.Key)
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
	if a.cfg.CustomMetricsPort > 0 {
		go a.serveCustomMetrics(ctx, a.cfg.CustomMetricsPort)
	}
	if a.cfg.OTLPPort > 0 {
		go a.serveOTLP(ctx, a.cfg.OTLPPort, a.cfg.OTLPBind)
	}
	defs.OTLPEnsure = func(port int) { a.ensureOTLP(ctx, port) }
	return client.Run(ctx, func(conn transport.Conn) error {
		a.connected.Store(true)
		a.lastConnect.Store(time.Now().Unix())
		a.lastError.Store("")
		a.writeStatus()
		defer func() { a.connected.Store(false); a.writeStatus() }()
		conn = &trackedConn{inner: conn, a: a}
		defer a.spoolPending()

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

		if err := a.sendHeartbeat(conn); err != nil {
			return err
		}
		a.drainSpool(conn)
		if err := a.sendMetrics(conn); err != nil {
			return err
		}
		if err := a.sendDiscovery(conn); err != nil {
			return err
		}

		mt := time.NewTicker(interval)
		defer mt.Stop()
		hb := time.NewTicker(heartbeatEvery)
		defer hb.Stop()
		dt := time.NewTicker(discoveryEvery)
		defer dt.Stop()
		dc := time.NewTicker(discoveryCheck)
		defer dc.Stop()
		pt := time.NewTicker(probeTick)
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
			case note := <-a.updateNote:
				detail, _ := json.Marshal(map[string]string{"from": note[0], "to": note[1]})
				a.seq++
				msg, err := protocol.Encode(protocol.TypeEvent, a.seq, protocol.AgentEvent{
					ServerID:  a.cfg.ServerID,
					Hostname:  a.cfg.Hostname,
					Kind:      "agent_update",
					Detail:    string(detail),
					Timestamp: time.Now().Unix(),
				})
				if err == nil {
					if err := conn.Send(msg); err != nil {
						return err
					}
				}
				select {
				case a.updateNoteDone <- struct{}{}:
				default:
				}
			case pts := <-a.custom:
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
					if err := a.observePoints(conn, pts); err != nil {
						return err
					}
				}
			case sp := <-a.spans:
				a.seq++
				msg, err := protocol.Encode(protocol.TypeSpans, a.seq, protocol.SpanBatch{
					ServerID: a.cfg.ServerID,
					Hostname: a.cfg.Hostname,
					Spans:    sp,
				})
				if err == nil {
					if err := conn.Send(msg); err != nil {
						return err
					}
				}
			case ri := <-a.rum:
				a.seq++
				msg, err := protocol.Encode(protocol.TypeRum, a.seq, protocol.RumBatch{
					ServerID: a.cfg.ServerID,
					Hostname: a.cfg.Hostname,
					Items:    ri,
				})
				if err == nil {
					if err := conn.Send(msg); err != nil {
						return err
					}
				}
			case o := <-a.profiles:
				if err := a.emitProfile(conn, o); err != nil {
					return err
				}
			case d := <-a.vhostDone:
				ch, err := a.emitOutcome(conn, d.service, d.service+"/"+d.probe.Name, d.o)
				if err != nil {
					return err
				}
				if ch {
					if err := a.sendFacts(conn); err != nil {
						return err
					}
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
		log.Printf("encode metrics failed: %v", err)
		return nil
	}
	if err := conn.Send(msg); err != nil {
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
		Pin:       a.EffectivePin(),
		Timestamp: time.Now().Unix(),
	})
	if err != nil {
		log.Printf("encode heartbeat failed: %v", err)
		return nil
	}
	a.writeStatus()
	return conn.Send(msg)
}

func (a *Agent) sendDiscovery(conn transport.Conn) error {
	facts := discovery.Collect()
	a.lastSignal = discovery.ChangeSignal()
	a.mu.Lock()
	a.facts = facts
	a.mu.Unlock()
	a.refreshActive()
	return a.sendFacts(conn)
}

func (a *Agent) sendFacts(conn transport.Conn) error {
	a.mu.Lock()
	facts := a.facts
	a.mu.Unlock()

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

func splitPaths(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		p = strings.TrimSpace(p)
		if p == "" || p == "off" || p == "/dev/null" || strings.HasPrefix(p, "syslog:") || strings.HasPrefix(p, "stderr") {
			continue
		}
		out = append(out, p)
	}
	return out
}

func (a *Agent) locationOverride(service, fact string) (string, bool) {
	sec := a.cfg.Overrides[service]
	if sec == nil {
		return "", false
	}
	for _, key := range []string{overrideKey(fact), fact} {
		if v := strings.TrimSpace(sec[key]); v != "" {
			return v, true
		}
	}
	return "", false
}

func overrideKey(fact string) string {
	var b strings.Builder
	for i, r := range fact {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				b.WriteByte('-')
			}
			b.WriteRune(r + 32)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (a *Agent) supported(d protocol.Definition) bool {
	if d.MinAgentVersion != "" && !versionAtLeast(buildinfo.Version, d.MinAgentVersion) {
		if !a.warnedUnsupported[d.Service] {
			log.Printf("service %s requires agent >= %s (have %s) - skipped until update", d.Service, d.MinAgentVersion, buildinfo.Version)
			a.warnedUnsupported[d.Service] = true
		}
		return false
	}
	if uns := defs.UnsupportedProbes(d); len(uns) > 0 {
		if !a.warnedUnsupported[d.Service] {
			log.Printf("service %s uses probe type(s) %v this agent (%s) does not know - skipped until update", d.Service, uns, buildinfo.Version)
			a.warnedUnsupported[d.Service] = true
		}
		return false
	}
	return true
}

func versionAtLeast(have, min string) bool {
	h, okH := versionNum(have)
	m, okM := versionNum(min)
	if !okH || !okM {
		return true
	}
	return h >= m
}

func versionNum(v string) (int, bool) {
	digits := strings.TrimLeftFunc(v, func(r rune) bool { return r < '0' || r > '9' })
	if digits == "" {
		return 0, false
	}
	n, err := strconv.Atoi(digits)
	if err != nil {
		return 0, false
	}
	return n, true
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
		if !a.supported(d) {
			continue
		}
		if len(d.RunOn) > 0 && !a.hostListed(d.RunOn) {
			continue
		}
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

type dueRun struct {
	def    protocol.Definition
	probes []protocol.Probe
}

func selectDueProbes(active []protocol.Definition, lastRun map[string]time.Time, now time.Time) []dueRun {
	var due []dueRun
	for _, d := range active {
		defInterval := time.Duration(d.IntervalSec) * time.Second
		if defInterval <= 0 {
			defInterval = time.Minute
		}
		var ready []protocol.Probe
		for _, p := range d.Probes {
			interval := defInterval
			if p.IntervalSec > 0 {
				interval = time.Duration(p.IntervalSec) * time.Second
			}
			key := d.Service + "/" + p.Name
			if now.Sub(lastRun[key]) >= interval {
				lastRun[key] = now
				ready = append(ready, p)
			}
		}
		if len(ready) > 0 {
			due = append(due, dueRun{def: d, probes: ready})
		}
	}
	return due
}

func (a *Agent) runDueProbes(conn transport.Conn) error {
	a.apmPass++
	defs.JournalCycle()
	if a.dropTailFDs.Swap(false) {
		for _, t := range a.tailers {
			t.CloseFDs()
		}
		for _, lt := range a.logTailers {
			lt.CloseFDs()
		}
	}
	a.mu.Lock()
	due := selectDueProbes(a.active, a.lastRun, time.Now())
	a.mu.Unlock()

	factsChanged := false
	for _, run := range due {
		d := run.def
		if a.serviceDenied(d.Service) {
			continue
		}
		for _, p := range run.probes {
			if p.Capability != "" {
				a.mu.Lock()
				facts := a.facts
				a.mu.Unlock()
				if !defs.HasCapability(facts, p.Capability) {
					continue
				}
			}
			if p.Type == "logtail" {
				if err := a.runLogtail(conn, d.Service, p); err != nil {
					return err
				}
				continue
			}
			if p.Type == "journal" {
				if err := a.runJournal(conn, d.Service, p); err != nil {
					return err
				}
				continue
			}
			if p.Type == "logs" {
				if a.denied("logs") {
					continue
				}
				if err := a.runLogs(conn, d.Service, p); err != nil {
					return err
				}
				continue
			}
			if p.Type == "procfact" {
				a.mu.Lock()
				facts := a.facts
				a.mu.Unlock()
				if pf := defs.ProcFacts(facts, p); len(pf) > 0 {
					if ch, _ := a.mergeServiceFacts(d.Service, pf); ch {
						factsChanged = true
					}
				}
				continue
			}
			if p.Type == "file" && p.Path == "" && p.PathFrom != "" {
				if ov, ok := a.locationOverride(d.Service, p.PathFrom); ok {
					p.Path = ov
				} else {
					a.mu.Lock()
					if sf := a.serviceFacts[d.Service]; sf != nil {
						p.Path = sf[p.PathFrom]
					}
					a.mu.Unlock()
				}
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
			if p.Type == "apmprofile" || p.Type == "apmdotnetprofile" || p.Type == "apmnodeprofile" {
				if a.denied("profiler") {
					continue
				}
				a.startProfile(d.Service, p)
				continue
			}
			if p.Type == "ebpfhttp" {
				if a.denied("ebpf") {
					a.stopEBPF()
					continue
				}
				if err := a.runEBPFHTTP(conn, d.Service, p); err != nil {
					return err
				}
				continue
			}
			if (p.Type == "sql" || p.Type == "redis" || p.Type == "tcp") && p.Address == "" && !p.Socket && p.PortProcess != "" {
				if port := a.resolvePort(p.PortProcess); port != "" {
					p.Address = "127.0.0.1:" + port
				}
			}
			if p.Type == "vhosts" {
				a.startVhosts(d.Service, p)
				continue
			}
			var o defs.Outcome
			switch p.Type {
			case "apmphp":
				o = defs.RunAPMPhp(d.Service, p, a.cfg.StateDir())
			case "apmdotnet":
				o = defs.RunAPMDotnet(d.Service, p, a.cfg.StateDir())
			case "apmnode":
				o = defs.RunAPMNode(d.Service, p, a.cfg.StateDir())
			default:
				o = defs.RunProbeWithSecrets(d.Service, p, a.resolveSecret)
			}
			ch, err := a.emitOutcome(conn, d.Service, d.Service+"/"+p.Name, o)
			if err != nil {
				return err
			}
			if ch {
				factsChanged = true
			}
		}
	}
	if factsChanged {
		return a.sendFacts(conn)
	}
	return nil
}

type probeDone struct {
	service string
	probe   protocol.Probe
	o       defs.Outcome
}

func (a *Agent) startVhosts(service string, p protocol.Probe) {
	key := service + "/" + p.Name
	a.mu.Lock()
	if a.vhostBusy[key] {
		a.mu.Unlock()
		return
	}
	a.vhostBusy[key] = true
	a.mu.Unlock()
	go func() {
		o := defs.RunProbe(service, p)
		a.mu.Lock()
		a.vhostBusy[key] = false
		a.mu.Unlock()
		select {
		case a.vhostDone <- probeDone{service: service, probe: p, o: o}:
		default:
		}
	}()
}

func (a *Agent) emitOutcome(conn transport.Conn, service, probeKey string, o defs.Outcome) (bool, error) {
	factsChanged := false
	checks := append([]protocol.CheckResult{o.Check}, o.Extra...)
	for i := range checks {
		checks[i].ServerID = a.cfg.ServerID
		checks[i].Hostname = a.cfg.Hostname
	}
	if len(checks) == 1 {
		a.seq++
		if msg, err := protocol.Encode(protocol.TypeCheck, a.seq, checks[0]); err == nil {
			if err := conn.Send(msg); err != nil {
				return false, err
			}
		}
	} else {
		a.seq++
		msg, err := protocol.Encode(protocol.TypeChecks, a.seq, protocol.CheckBatch{
			ServerID: a.cfg.ServerID,
			Hostname: a.cfg.Hostname,
			Checks:   checks,
		})
		if err == nil {
			if err := conn.Send(msg); err != nil {
				return false, err
			}
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
				return false, err
			}
		}
		if err := a.observePoints(conn, o.Metrics); err != nil {
			return false, err
		}
	}
	if len(o.Facts) > 0 {
		ch, integrity := a.mergeServiceFacts(service, o.Facts)
		if ch {
			factsChanged = true
		}
		if err := a.sendIntegrity(conn, service, integrity); err != nil {
			return false, err
		}
	}
	if o.Check.Status == "ok" || len(o.InvFacts) > 0 {
		if a.setProbeFacts(probeKey, o.InvFacts) {
			factsChanged = true
		}
	}
	for _, ev := range o.Events {
		ev.ServerID = a.cfg.ServerID
		ev.Hostname = a.cfg.Hostname
		if ev.Timestamp == 0 {
			ev.Timestamp = time.Now().Unix()
		}
		log.Printf("%s: %s", ev.Kind, ev.Detail)
		a.seq++
		emsg, err := protocol.Encode(protocol.TypeEvent, a.seq, ev)
		if err != nil {
			continue
		}
		if err := conn.Send(emsg); err != nil {
			return false, err
		}
	}
	if len(o.ProfileStacks) > 0 {
		pb := o.ProfileMeta
		pb.ServerID = a.cfg.ServerID
		pb.Hostname = a.cfg.Hostname
		pb.Timestamp = time.Now().Unix()
		pb.Stacks = o.ProfileStacks
		a.seq++
		pmsg, err := protocol.Encode(protocol.TypeProfile, a.seq, pb)
		if err == nil {
			if err := conn.Send(pmsg); err != nil {
				return false, err
			}
		}
	}
	return factsChanged, nil
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

func (a *Agent) hostListed(hosts []string) bool {
	for _, h := range hosts {
		if h == a.cfg.Hostname || h == a.cfg.ServerID {
			return true
		}
	}
	return false
}

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
		if ov, ok := a.locationOverride(service, p.PathFrom); ok {
			paths = splitPaths(ov)
		} else {
			a.mu.Lock()
			if facts := a.serviceFacts[service]; facts != nil {
				paths = splitPaths(facts[p.PathFrom])
			}
			a.mu.Unlock()
		}
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
		if t != nil {
			t.CloseFDs()
		}
		t = defs.NewTailer(paths)
		a.tailers[key] = t
	}
	pts, events, err := t.Sample(p.Counters, time.Now())
	if err != nil {
		check.Status = "fail"
		check.Error = err.Error()
		return a.sendCheck(conn, check)
	}
	check.Status = "ok"
	if err := a.sendCheck(conn, check); err != nil {
		return err
	}
	return a.sendTailOutput(conn, events, pts)
}

func (a *Agent) sendTailOutput(conn transport.Conn, events []protocol.AgentEvent, pts []protocol.MetricPoint) error {
	for _, ev := range events {
		ev.ServerID = a.cfg.ServerID
		ev.Hostname = a.cfg.Hostname
		if ev.Timestamp == 0 {
			ev.Timestamp = time.Now().Unix()
		}
		log.Printf("%s: %s", ev.Kind, ev.Detail)
		a.seq++
		if msg, err := protocol.Encode(protocol.TypeEvent, a.seq, ev); err == nil {
			if err := conn.Send(msg); err != nil {
				return err
			}
		}
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

func (a *Agent) runJournal(conn transport.Conn, service string, p protocol.Probe) error {
	key := service + "/" + p.Name
	j := a.journals[key]
	if j == nil {
		j = defs.NewJournalTailer(key)
		a.journals[key] = j
	}
	check := protocol.CheckResult{
		ServerID:  a.cfg.ServerID,
		Hostname:  a.cfg.Hostname,
		CheckID:   key,
		Kind:      "journal",
		Target:    strings.Join(p.Idents, ","),
		Timestamp: time.Now().Unix(),
	}
	pts, events, err := j.Sample(p.Idents, p.Counters, time.Now())
	if err != nil {
		check.Status = "fail"
		check.Error = err.Error()
		return a.sendCheck(conn, check)
	}
	check.Status = "ok"
	if err := a.sendCheck(conn, check); err != nil {
		return err
	}
	return a.sendTailOutput(conn, events, pts)
}

const logMaxLinesPerWindow = 2000

func (a *Agent) runLogs(conn transport.Conn, service string, p protocol.Probe) error {
	key := service + "/" + p.Name
	t := a.logTailers[key]
	if t == nil {
		t = defs.NewLogTailer(key)
		a.logTailers[key] = t
	}
	a.mu.Lock()
	if a.logDeep[service] {
		p.MinLevel = "debug"
	}
	a.mu.Unlock()
	if p.PathFrom != "" {
		var fromPaths []string
		if ov, ok := a.locationOverride(service, p.PathFrom); ok {
			fromPaths = splitPaths(ov)
		} else {
			a.mu.Lock()
			if facts := a.serviceFacts[service]; facts != nil {
				fromPaths = splitPaths(facts[p.PathFrom])
			}
			a.mu.Unlock()
		}
		if len(fromPaths) > 0 {
			p.Paths = fromPaths
			p.Path = ""
		}
	}
	lines, err := t.Collect(service, p, time.Now())
	if err != nil {
		log.Printf("logs %s: %v", key, err)
	}
	for _, fn := range t.FloodNotes() {
		detail, _ := json.Marshal(map[string]any{
			"service": service, "path": fn.Path,
			"mbPerCycle": float64(int(float64(fn.BytesCycle)/1048576*10+0.5)) / 10,
		})
		a.seq++
		if msg, err := protocol.Encode(protocol.TypeEvent, a.seq, protocol.AgentEvent{
			ServerID: a.cfg.ServerID, Hostname: a.cfg.Hostname,
			Kind: "log_source_flooding", Detail: string(detail), Timestamp: time.Now().Unix(),
		}); err == nil {
			conn.Send(msg)
		}
	}
	if len(lines) == 0 {
		return nil
	}
	lines = a.capLogs(conn, lines)
	if len(lines) == 0 {
		return nil
	}
	a.seq++
	msg, err := protocol.Encode(protocol.TypeLogs, a.seq, protocol.LogBatch{
		ServerID: a.cfg.ServerID,
		Hostname: a.cfg.Hostname,
		Lines:    lines,
	})
	if err != nil {
		return nil
	}
	return conn.Send(msg)
}

func (a *Agent) capLogs(conn transport.Conn, lines []protocol.LogLine) []protocol.LogLine {
	now := time.Now()
	if now.After(a.logBudgetAt) {
		a.logBudget = logMaxLinesPerWindow
		a.logBudgetAt = now.Add(60 * time.Second)
		a.logCapped = false
	}
	if len(lines) <= a.logBudget {
		a.logBudget -= len(lines)
		return lines
	}
	sort.SliceStable(lines, func(i, j int) bool {
		return defs.LogRank(lines[i].Level) < defs.LogRank(lines[j].Level)
	})
	kept := lines
	if a.logBudget < len(lines) {
		kept = lines[:a.logBudget]
	}
	dropped := len(lines) - len(kept)
	a.logBudget = 0
	if dropped > 0 && !a.logCapped {
		a.logCapped = true
		detail, _ := json.Marshal(map[string]any{"dropped": dropped, "windowSec": 60})
		a.seq++
		if msg, err := protocol.Encode(protocol.TypeEvent, a.seq, protocol.AgentEvent{
			ServerID: a.cfg.ServerID, Hostname: a.cfg.Hostname,
			Kind: "log_volume_capped", Detail: string(detail), Timestamp: time.Now().Unix(),
		}); err == nil {
			conn.Send(msg)
		}
	}
	return kept
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
		if p.V3 {
			c, ok := a.resolveSecret(p.Secret)
			if !ok {
				return a.sendCheck(conn, protocol.CheckResult{
					ServerID: a.cfg.ServerID, Hostname: a.cfg.Hostname,
					CheckID: service + "/" + p.Name, Kind: "traps", Target: "udp/" + strconv.Itoa(port),
					Status: "fail", Error: "secret " + p.Secret + " not set (v3 traps need USM creds)",
					Timestamp: time.Now().Unix(),
				})
			}
			l.SetV3(defs.V3Auth{
				User: c.User, AuthProto: p.AuthProto, PrivProto: p.PrivProto,
				AuthPass: c.Pass, PrivPass: c.Priv,
			})
		}
		l.Start()
		a.trapL[port] = l
		log.Printf("trap listener started on udp/%d (v3=%v)", port, p.V3)
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
				for key := range a.lastRun {
					if strings.HasPrefix(key, svc+"/") {
						delete(a.lastRun, key)
					}
				}
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
	if err := a.sendProbeMetrics(conn, pts); err != nil {
		return err
	}
	return a.sendSyslogLines(conn, l.DrainLines())
}

var syslogSevLevel = [8]string{"error", "error", "error", "error", "warn", "notice", "info", "debug"}

func (a *Agent) sendSyslogLines(conn transport.Conn, raw []defs.SyslogLine) error {
	if len(raw) == 0 || a.denied("logs") {
		return nil
	}
	minRank := defs.LogRank("notice")
	var lines []protocol.LogLine
	for _, s := range raw {
		sev := s.Severity
		if sev < 0 || sev > 7 {
			sev = 6
		}
		level := syslogSevLevel[sev]
		if defs.LogRank(level) > minRank {
			continue
		}
		lines = append(lines, protocol.LogLine{
			Ts: s.Ts, Service: "syslog", Level: level,
			Message: defs.ScrubDefault(s.Source + " " + s.Message),
		})
	}
	if len(lines) == 0 {
		return nil
	}
	lines = a.capLogs(conn, lines)
	if len(lines) == 0 {
		return nil
	}
	a.seq++
	msg, err := protocol.Encode(protocol.TypeLogs, a.seq, protocol.LogBatch{
		ServerID: a.cfg.ServerID,
		Hostname: a.cfg.Hostname,
		Lines:    lines,
	})
	if err != nil {
		return nil
	}
	return conn.Send(msg)
}

func (a *Agent) startProfile(service string, p protocol.Probe) {
	a.mu.Lock()
	if a.profiling[service] {
		a.mu.Unlock()
		return
	}
	a.profiling[service] = true
	a.mu.Unlock()
	go func() {
		var o defs.Outcome
		switch p.Type {
		case "apmdotnetprofile":
			o = defs.RunAPMDotnetProfile(service, p, a.cfg.StateDir())
		case "apmnodeprofile":
			o = defs.RunAPMNodeProfile(service, p)
		default:
			o = defs.RunAPMProfile(service, p)
		}
		a.mu.Lock()
		a.profiling[service] = false
		a.mu.Unlock()
		select {
		case a.profiles <- o:
		default:
		}
	}()
}

func (a *Agent) emitProfile(conn transport.Conn, o defs.Outcome) error {
	o.Check.ServerID = a.cfg.ServerID
	o.Check.Hostname = a.cfg.Hostname
	if err := a.sendCheck(conn, o.Check); err != nil {
		return err
	}
	if err := a.sendProbeMetrics(conn, o.Metrics); err != nil {
		return err
	}
	if len(o.Facts) > 0 {
		if svc, _, ok := strings.Cut(o.Check.CheckID, "/"); ok {
			_, _ = a.mergeServiceFacts(svc, o.Facts)
		}
	}
	if len(o.ProfileStacks) > 0 {
		pb := o.ProfileMeta
		pb.ServerID = a.cfg.ServerID
		pb.Hostname = a.cfg.Hostname
		pb.Timestamp = time.Now().Unix()
		pb.Stacks = o.ProfileStacks
		a.seq++
		msg, err := protocol.Encode(protocol.TypeProfile, a.seq, pb)
		if err == nil {
			if err := conn.Send(msg); err != nil {
				return err
			}
		}
	}
	return nil
}

func rate(cur, prev uint64, secs float64) float64 {
	if cur < prev {
		prev = 0
	}
	return float64(int(float64(cur-prev)/secs*1000+0.5)) / 1000
}

func (a *Agent) denied(cap string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.deny[cap]
}

func (a *Agent) serviceDenied(svc string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.denySvc[svc]
}

func (a *Agent) stopEBPF() {
	a.apmWant = nil
	a.apmCurPorts = nil
	a.apmCurDown = nil
	if a.apmEngine == nil {
		a.apmErr = nil
		return
	}
	a.apmEngine.Close()
	a.apmEngine = nil
	a.apmErr = nil
	log.Print("ebpf http engine stopped: denied from the console")
}

func (a *Agent) runEBPFHTTP(conn transport.Conn, service string, p protocol.Probe) error {
	ports := append([]int(nil), p.Ports...)
	if p.PortProcess != "" {
		for _, rp := range a.resolvePorts(p.PortProcess) {
			found := false
			for _, e := range ports {
				if e == rp {
					found = true
					break
				}
			}
			if !found {
				ports = append(ports, rp)
			}
		}
	}
	sort.Ints(ports)
	check := protocol.CheckResult{
		ServerID:  a.cfg.ServerID,
		Hostname:  a.cfg.Hostname,
		CheckID:   service + "/" + p.Name,
		Kind:      "ebpfhttp",
		Target:    fmt.Sprintf("kprobe tcp ports %v", ports),
		Timestamp: time.Now().Unix(),
	}
	if len(ports) == 0 {
		delete(a.apmWant, service)
		check.Status = "fail"
		check.Error = "no listening tcp ports discovered for process " + p.PortProcess
		return a.sendCheck(conn, check)
	}
	down := map[string][]int{}
	for _, c := range p.Downstream {
		down[c.Name] = c.Ports
	}
	if a.apmWant == nil {
		a.apmWant = map[string]apmWantSet{}
	}
	a.apmWant[service] = apmWantSet{ports: ports, down: down, seen: time.Now()}
	unionPorts, unionDown := apmUnion(a.apmWant, time.Now())
	if a.apmEngine != nil && (!intsEqual(unionPorts, a.apmCurPorts) || !downEqual(unionDown, a.apmCurDown)) {
		a.apmEngine.Close()
		a.apmEngine = nil
		a.apmErr = nil
		log.Printf("ebpf http engine restarting: ports %v -> %v", a.apmCurPorts, unionPorts)
	}
	if a.apmEngine == nil {
		if a.apmErr == nil {
			a.apmEngine = apm.NewEngine()
			if err := a.apmEngine.Start(unionPorts, unionDown); err != nil {
				a.apmErr = err
				a.apmEngine = nil
				log.Printf("ebpf http engine unavailable: %v", err)
			} else {
				a.apmCurPorts = unionPorts
				a.apmCurDown = unionDown
				a.apmDrainPass = a.apmPass
				log.Printf("ebpf http engine started, ports %v downstream %v", unionPorts, unionDown)
			}
		}
		if a.apmEngine == nil {
			check.Status = "fail"
			check.Error = a.apmErr.Error()
			return a.sendCheck(conn, check)
		}
		check.Status = "ok"
		return a.sendCheck(conn, check)
	}
	if a.apmDrainPass == a.apmPass {
		check.Status = "ok"
		return a.sendCheck(conn, check)
	}
	a.apmDrainPass = a.apmPass
	snap, derr := a.apmEngine.Drain()
	if derr != nil {
		check.Status = "fail"
		check.Error = derr.Error()
		return a.sendCheck(conn, check)
	}
	check.Status = "ok"
	if err := a.sendCheck(conn, check); err != nil {
		return err
	}
	var pts []protocol.MetricPoint
	for port, s := range snap.HTTP {
		secs := s.Elapsed.Seconds()
		if secs <= 0 {
			continue
		}
		tags := map[string]string{"port": strconv.Itoa(int(port))}
		pts = append(pts,
			protocol.MetricPoint{Name: "apm.http.req_rate", Value: rate(s.Count, 0, secs), Tags: tags},
			protocol.MetricPoint{Name: "apm.http.error_rate", Value: rate(s.Err5xx, 0, secs), Tags: tags},
			protocol.MetricPoint{Name: "apm.http.client_error_rate", Value: rate(s.Err4xx, 0, secs), Tags: tags},
		)
		if s.Count > 0 {
			pts = append(pts,
				protocol.MetricPoint{Name: "apm.http.p50_ms", Value: s.P50Ms, Tags: tags},
				protocol.MetricPoint{Name: "apm.http.p95_ms", Value: s.P95Ms, Tags: tags},
				protocol.MetricPoint{Name: "apm.http.max_ms", Value: s.MaxMs, Tags: tags},
			)
		}
	}
	for comp, s := range snap.Downstream {
		secs := s.Elapsed.Seconds()
		if secs <= 0 {
			continue
		}
		tags := map[string]string{"component": comp}
		pts = append(pts, protocol.MetricPoint{Name: "apm.backend.call_rate", Value: rate(s.Count, 0, secs), Tags: tags})
		if s.Count > 0 {
			pts = append(pts,
				protocol.MetricPoint{Name: "apm.backend.p50_ms", Value: s.P50Ms, Tags: tags},
				protocol.MetricPoint{Name: "apm.backend.p95_ms", Value: s.P95Ms, Tags: tags},
				protocol.MetricPoint{Name: "apm.backend.max_ms", Value: s.MaxMs, Tags: tags},
			)
		}
	}
	return a.sendProbeMetrics(conn, pts)
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
		log.Printf("encode check failed: %v", err)
		return nil
	}
	return conn.Send(msg)
}

type factChange struct {
	Key, Old, New string
}

func (a *Agent) sendIntegrity(conn transport.Conn, service string, changes []factChange) error {
	for _, c := range changes {
		name := strings.TrimSuffix(c.Key, "Sha256")
		detail, err := json.Marshal(map[string]string{
			"service": service, "file": name, "oldSha256": c.Old, "newSha256": c.New,
		})
		if err != nil {
			continue
		}
		log.Printf("integrity: %s/%s content changed", service, name)
		a.seq++
		msg, err := protocol.Encode(protocol.TypeEvent, a.seq, protocol.AgentEvent{
			ServerID:  a.cfg.ServerID,
			Hostname:  a.cfg.Hostname,
			Kind:      "integrity",
			Detail:    string(detail),
			Timestamp: time.Now().Unix(),
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

func (a *Agent) mergeServiceFacts(service string, facts map[string]string) (bool, []factChange) {
	a.mu.Lock()
	defer a.mu.Unlock()
	cur := a.serviceFacts[service]
	if cur == nil {
		cur = map[string]string{}
		a.serviceFacts[service] = cur
	}
	changed := false
	var integrity []factChange
	for k, v := range facts {
		if cur[k] != v {
			if strings.HasSuffix(k, "Sha256") && cur[k] != "" {
				integrity = append(integrity, factChange{Key: k, Old: cur[k], New: v})
			}
			cur[k] = v
			changed = true
		}
	}
	return changed, integrity
}

func tailConfigSig(defsList []protocol.Definition, deny, denySvc, logDeep map[string]bool) uint64 {
	items := make([]string, 0, len(defsList))
	for _, d := range defsList {
		b, _ := json.Marshal(d)
		items = append(items, string(b))
	}
	sort.Strings(items)
	h := fnv.New64a()
	for _, it := range items {
		h.Write([]byte(it))
		h.Write([]byte{0})
	}
	for _, m := range []map[string]bool{deny, denySvc, logDeep} {
		b, _ := json.Marshal(m)
		h.Write(b)
		h.Write([]byte{0})
	}
	return h.Sum64()
}

func (a *Agent) handleDownstream(m protocol.Message, kick, dkick chan struct{}) {
	switch m.Type {
	case protocol.TypeAck:
		a.lastAck.Store(time.Now().Unix())
		a.ackPending(m.Seq)
	case protocol.TypeConfig:
		var set protocol.DefinitionSet
		if err := json.Unmarshal(m.Payload, &set); err != nil {
			return
		}
		verified := defs.Verify(set, a.publisherKey)
		deny := map[string]bool{}
		for _, d := range set.Deny {
			deny[d] = true
		}
		allow := map[string]bool{}
		for _, al := range set.Allow {
			allow[al] = true
		}
		defs.SetStagingDenied(deny["staged"])
		defs.SetDeepTraceAllowed(allow["deeptrace"])
		defs.SetNodeProfileAllowed(allow["nodeprofile"])
		a.setRumSites(set.RumSites)
		denySvc := map[string]bool{}
		for _, sv := range set.DenyServices {
			denySvc[sv] = true
		}
		logDeep := map[string]bool{}
		for _, sv := range set.LogDeep {
			logDeep[sv] = true
		}
		sig := tailConfigSig(verified, deny, denySvc, logDeep)
		a.mu.Lock()
		tailChanged := !a.haveTailSig || a.lastTailSig != sig
		a.lastTailSig = sig
		a.haveTailSig = true
		a.defs = verified
		a.roles = set.Roles
		a.deny = deny
		a.denySvc = denySvc
		a.logDeep = logDeep
		a.mu.Unlock()
		if len(set.Deny) > 0 {
			log.Printf("console denies: %v", set.Deny)
		}
		if len(set.DenyServices) > 0 {
			log.Printf("console denies services: %v", set.DenyServices)
		}
		log.Printf("definitions received: %d verified of %d", len(verified), len(set.Definitions))
		if tailChanged {
			a.dropTailFDs.Store(true)
		}
		a.applyPushedPin(set.Pin)
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
			a.lastRotate.Store(time.Now().Unix())
			a.writeStatus()
			log.Print("per-server key rotated")
		case "updateNow":
			if a.updateKick != nil {
				select {
				case a.updateKick <- struct{}{}:
				default:
				}
			}
		case "publicIP":
			if c.Key != "" {
				defs.SetPublicIP(c.Key)
			}
		case "uninstall":
			if !defs.VerifyUninstallOrder(c.Key, a.publisherKey, a.cfg.ServerID) {
				log.Print("uninstall order rejected: signature or uuid mismatch")
				return
			}
			log.Print("signed uninstall order accepted - removing the agent from this host")
			if err := spawnUninstall(a.cfg.Dir()); err != nil {
				log.Printf("uninstall spawn failed: %v", err)
			}
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
