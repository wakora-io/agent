package agent

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"wakora.io/agent/internal/buffer"
	"wakora.io/agent/internal/config"
	"wakora.io/agent/internal/protocol"
)

func spooledBeats(t *testing.T, ring *buffer.Ring) int {
	n := 0
	err := ring.Drain(func(line []byte) error {
		var m protocol.Message
		if json.Unmarshal(line, &m) == nil && m.Type == protocol.TypeHeartbeat {
			n++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestOfflineBeatStartsAtTheDrop(t *testing.T) {
	ring := buffer.New(filepath.Join(t.TempDir(), "spool.jsonl"), 1<<20, time.Hour)
	a := &Agent{cfg: &config.Config{ServerID: "x"}, ring: ring, dropped: make(chan struct{}, 1)}
	a.connected.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.offlineLoop(ctx, time.Hour, time.Hour)

	time.Sleep(50 * time.Millisecond)
	a.connected.Store(false)
	a.dropped <- struct{}{}
	time.Sleep(100 * time.Millisecond)
	if n := spooledBeats(t, ring); n != 1 {
		t.Fatalf("spooled %d heartbeats at the drop, want 1", n)
	}
}

func TestOfflineBeatKeepsTheHeartbeatCadence(t *testing.T) {
	ring := buffer.New(filepath.Join(t.TempDir(), "spool.jsonl"), 1<<20, time.Hour)
	a := &Agent{cfg: &config.Config{ServerID: "x"}, ring: ring, dropped: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.offlineLoop(ctx, time.Hour, 40*time.Millisecond)

	time.Sleep(230 * time.Millisecond)
	cancel()
	if n := spooledBeats(t, ring); n < 4 {
		t.Fatalf("spooled %d heartbeats in 230ms at a 40ms cadence, want at least 4", n)
	}
}

func TestOfflineBeatSilentWhileConnected(t *testing.T) {
	ring := buffer.New(filepath.Join(t.TempDir(), "spool.jsonl"), 1<<20, time.Hour)
	a := &Agent{cfg: &config.Config{ServerID: "x"}, ring: ring, dropped: make(chan struct{}, 1)}
	a.connected.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.offlineLoop(ctx, time.Hour, 20*time.Millisecond)

	time.Sleep(120 * time.Millisecond)
	cancel()
	if n := spooledBeats(t, ring); n != 0 {
		t.Fatalf("spooled %d heartbeats while connected", n)
	}
}
