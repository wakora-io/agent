package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"wakora.io/agent/internal/buffer"
	"wakora.io/agent/internal/config"
	"wakora.io/agent/internal/protocol"
	"wakora.io/agent/internal/transport"
)

type fakeGateway struct {
	mu         sync.Mutex
	heartbeats []protocol.Heartbeat
	points     map[string]float64
	factKinds  map[string]int
	checks     map[string]string
	conns      int
	dropFirst  bool
	defSet     protocol.DefinitionSet
}

func (g *fakeGateway) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ws" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("X-Wakora-Key") == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		c.SetReadLimit(1 << 22)
		g.mu.Lock()
		g.conns++
		n := g.conns
		g.mu.Unlock()

		ctx := r.Context()
		raw, _ := json.Marshal(g.defSet)
		cfg, _ := json.Marshal(protocol.Message{Type: protocol.TypeConfig, Payload: raw})
		if err := c.Write(ctx, websocket.MessageText, cfg); err != nil {
			return
		}
		received := 0
		for {
			_, data, err := c.Read(ctx)
			if err != nil {
				return
			}
			var m protocol.Message
			if json.Unmarshal(data, &m) != nil {
				continue
			}
			received++
			g.record(m)
			if g.dropFirst && n == 1 && received >= 3 {
				c.Close(websocket.StatusGoingAway, "test drop")
				return
			}
			if m.Seq != 0 {
				ack, _ := json.Marshal(protocol.Message{Type: protocol.TypeAck, Seq: m.Seq})
				if err := c.Write(ctx, websocket.MessageText, ack); err != nil {
					return
				}
			}
		}
	}
}

func (g *fakeGateway) record(m protocol.Message) {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch m.Type {
	case protocol.TypeHeartbeat:
		var hb protocol.Heartbeat
		if json.Unmarshal(m.Payload, &hb) == nil {
			g.heartbeats = append(g.heartbeats, hb)
		}
	case protocol.TypeMetrics:
		var b protocol.MetricsBatch
		if json.Unmarshal(m.Payload, &b) == nil {
			for _, p := range b.Points {
				g.points[p.Name] = p.Value
			}
		}
	case protocol.TypeDiscovery:
		var d protocol.DiscoverySnapshot
		if json.Unmarshal(m.Payload, &d) == nil {
			kinds := map[string]int{}
			for _, f := range d.Facts {
				kinds[f.Kind]++
			}
			g.factKinds = kinds
		}
	case protocol.TypeCheck:
		var c protocol.CheckResult
		if json.Unmarshal(m.Payload, &c) == nil {
			g.checks[c.CheckID] = c.Status
		}
	}
}

func (g *fakeGateway) snapshot() (hb int, conns int, points map[string]float64, kinds map[string]int, checks map[string]string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	points = map[string]float64{}
	for k, v := range g.points {
		points[k] = v
	}
	kinds = map[string]int{}
	for k, v := range g.factKinds {
		kinds[k] = v
	}
	checks = map[string]string{}
	for k, v := range g.checks {
		checks[k] = v
	}
	return len(g.heartbeats), g.conns, points, kinds, checks
}

func TestAgentCycleE2E(t *testing.T) {
	oldTick := probeTick
	probeTick = 300 * time.Millisecond
	defer func() { probeTick = oldTick }()

	dir := t.TempDir()
	artifact := filepath.Join(dir, "backup.tar")
	if err := os.WriteFile(artifact, []byte("dump"), 0o644); err != nil {
		t.Fatal(err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	def := fmt.Sprintf(`{"service":"itest","match":{"init":"*"},"intervalSec":1,"probes":[{"name":"artifact","type":"file","path":%q,"age":true}]}`, artifact)
	badDef := `{"service":"evil","match":{"init":"*"},"intervalSec":1,"probes":[{"name":"x","type":"exec","command":"id"}]}`
	gw := &fakeGateway{
		points:    map[string]float64{},
		checks:    map[string]string{},
		dropFirst: true,
		defSet: protocol.DefinitionSet{Definitions: []protocol.SignedDefinition{
			{Def: []byte(def), Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(def)))},
			{Def: []byte(badDef), Sig: base64.StdEncoding.EncodeToString([]byte("forged signature"))},
		}},
	}

	srv := httptest.NewServer(gw.handler(t))
	defer srv.Close()

	cfg, err := config.Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg.ServerID = "itest-uuid"
	cfg.Hostname = "itest-host"

	ring := buffer.New(filepath.Join(dir, "buffer.jsonl"), 1<<20, time.Hour)
	a := New(cfg, ring, base64.StdEncoding.EncodeToString(pub))
	client := &transport.Client{
		Endpoint: "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws",
		Dialer:   transport.NewWSDialer(func() string { return "testkey" }, ""),
		Backoff:  200 * time.Millisecond,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		_ = a.Run(ctx, client, 400*time.Millisecond, time.Second, 2*time.Second, time.Hour)
		close(done)
	}()

	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		hb, conns, points, kinds, checks := gw.snapshot()
		_, hasExists := points["svc.itest.artifact.exists"]
		age, hasAge := points["svc.itest.artifact.age_sec"]
		if hb >= 2 && conns >= 2 && hasExists && hasAge && age >= 0 &&
			kinds["init"] > 0 && checks["itest/artifact"] == "ok" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	cancel()
	<-done

	hb, conns, points, kinds, checks := gw.snapshot()
	if hb < 2 {
		t.Fatalf("want >=2 heartbeats, got %d", hb)
	}
	if conns < 2 {
		t.Fatalf("want reconnect after drop (>=2 connections), got %d", conns)
	}
	if v, ok := points["svc.itest.artifact.exists"]; !ok || v != 1 {
		t.Fatalf("probe exists metric missing/wrong: %v %v (points: %v)", v, ok, points)
	}
	if v, ok := points["svc.itest.artifact.age_sec"]; !ok || v < 0 || v > 300 {
		t.Fatalf("probe age metric missing/wrong: %v %v", v, ok)
	}
	if checks["itest/artifact"] != "ok" {
		t.Fatalf("check result not ok: %v", checks)
	}
	if kinds["init"] == 0 || kinds["process"] == 0 {
		t.Fatalf("discovery facts missing: %v", kinds)
	}
	for name := range points {
		if strings.HasPrefix(name, "svc.evil.") {
			t.Fatalf("forged definition executed: %s", name)
		}
	}
	if _, ok := checks["evil/x"]; ok {
		t.Fatal("forged definition produced a check")
	}

	a.pmu.Lock()
	pending := len(a.pending)
	a.pmu.Unlock()
	if pending > 0 {
		t.Logf("note: %d message(s) still unacked at shutdown (in-flight at cancel)", pending)
	}
}
