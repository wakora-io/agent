package agent

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"wakora.io/agent/internal/buffer"
	"wakora.io/agent/internal/config"
	"wakora.io/agent/internal/discovery"
	"wakora.io/agent/internal/metrics"
	"wakora.io/agent/internal/protocol"
	"wakora.io/agent/internal/transport"
)

type Agent struct {
	cfg    *config.Config
	client *transport.Client
	ring   *buffer.Ring
	seq    uint64
}

func New(cfg *config.Config, client *transport.Client, ring *buffer.Ring) *Agent {
	return &Agent{cfg: cfg, client: client, ring: ring}
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

func (a *Agent) Run(ctx context.Context, interval time.Duration) error {
	return a.client.Run(ctx, func(conn transport.Conn) error {
		a.drainSpool(conn)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				a.seq++
				msg, err := protocol.Encode(protocol.TypeMetrics, a.seq, a.collect())
				if err != nil {
					continue
				}
				if err := conn.Send(msg); err != nil {
					if raw, e := json.Marshal(msg); e == nil {
						_ = a.ring.Append(raw)
					}
					return err
				}
			}
		}
	})
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
