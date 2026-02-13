package agent

import (
	"context"
	"encoding/json"
	"log"
	"sync/atomic"
	"time"

	"wakora.io/agent/internal/buffer"
	"wakora.io/agent/internal/buildinfo"
	"wakora.io/agent/internal/config"
	"wakora.io/agent/internal/discovery"
	"wakora.io/agent/internal/metrics"
	"wakora.io/agent/internal/protocol"
	"wakora.io/agent/internal/transport"
)

type Agent struct {
	cfg  *config.Config
	ring *buffer.Ring
	key  atomic.Value
	seq  uint64
}

func New(cfg *config.Config, ring *buffer.Ring) *Agent {
	a := &Agent{cfg: cfg, ring: ring}
	a.key.Store(cfg.Key)
	return a
}

func (a *Agent) Key() string {
	v, _ := a.key.Load().(string)
	return v
}

func (a *Agent) collect() protocol.MetricsBatch {
	h := metrics.Collect()
	return protocol.MetricsBatch{
		ServerID:  a.cfg.ServerID,
		Hostname:  a.cfg.Hostname,
		Timestamp: h.Timestamp,
		Points: []protocol.MetricPoint{
			{Name: "load1", Value: h.Load1},
			{Name: "mem_total_kb", Value: float64(h.MemTotalKB)},
			{Name: "mem_free_kb", Value: float64(h.MemFreeKB)},
			{Name: "uptime_sec", Value: h.UptimeSec},
		},
	}
}

func (a *Agent) Run(ctx context.Context, client *transport.Client, interval, heartbeatEvery time.Duration) error {
	return client.Run(ctx, func(conn transport.Conn) error {
		a.drainSpool(conn)
		if err := a.sendHeartbeat(conn); err != nil {
			return err
		}
		if err := a.sendMetrics(conn); err != nil {
			return err
		}

		kick := make(chan struct{}, 1)
		readErr := make(chan error, 1)
		go func() {
			for {
				m, err := conn.Recv()
				if err != nil {
					readErr <- err
					return
				}
				a.handleDownstream(m, kick)
			}
		}()

		mt := time.NewTicker(interval)
		defer mt.Stop()
		hb := time.NewTicker(heartbeatEvery)
		defer hb.Stop()
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
			case <-hb.C:
				if err := a.sendHeartbeat(conn); err != nil {
					return err
				}
			case <-mt.C:
				if err := a.sendMetrics(conn); err != nil {
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

func (a *Agent) handleDownstream(m protocol.Message, kick chan struct{}) {
	switch m.Type {
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
	f := discovery.Enumerate()
	log.Printf("discovery: %d processes", len(f.Processes))
}
