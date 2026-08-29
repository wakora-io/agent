package agent

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"wakora.io/agent/internal/buffer"
	"wakora.io/agent/internal/protocol"
)

type stubConn struct{ sent int }

func (s *stubConn) Send(protocol.Message) error     { s.sent++; return nil }
func (s *stubConn) Recv() (protocol.Message, error) { select {} }
func (s *stubConn) Ping(ctx context.Context) error  { return nil }
func (s *stubConn) Close() error                    { return nil }

func TestPendingBackpressureReleasesOnAck(t *testing.T) {
	oldCap, oldTO := pendingCap, pendingStallTimeout
	pendingCap, pendingStallTimeout = 2, 2*time.Second
	defer func() { pendingCap, pendingStallTimeout = oldCap, oldTO }()

	a := &Agent{pending: map[uint64][]byte{}, pendingFreed: make(chan struct{}, 1)}
	if _, err := a.trackPending(protocol.Message{Seq: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.trackPending(protocol.Message{Seq: 2}); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := a.trackPending(protocol.Message{Seq: 3})
		done <- err
	}()
	select {
	case <-done:
		t.Fatal("trackPending must block while pending is full")
	case <-time.After(150 * time.Millisecond):
	}
	a.ackPending(1)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("trackPending after ack: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("trackPending did not unblock after ack freed a slot")
	}
}

func TestSendStallSpoolsAndErrors(t *testing.T) {
	oldCap, oldTO := pendingCap, pendingStallTimeout
	pendingCap, pendingStallTimeout = 1, 150*time.Millisecond
	defer func() { pendingCap, pendingStallTimeout = oldCap, oldTO }()

	ringPath := filepath.Join(t.TempDir(), "buf.jsonl")
	a := &Agent{
		pending:      map[uint64][]byte{},
		pendingFreed: make(chan struct{}, 1),
		ring:         buffer.New(ringPath, 1<<20, 0),
	}
	inner := &stubConn{}
	tc := &trackedConn{inner: inner, a: a}

	if err := tc.Send(protocol.Message{Seq: 1, Type: protocol.TypeMetrics}); err != nil {
		t.Fatalf("first send: %v", err)
	}
	if inner.sent != 1 {
		t.Fatalf("first message should reach the wire, sent=%d", inner.sent)
	}

	err := tc.Send(protocol.Message{Seq: 2, Type: protocol.TypeMetrics})
	if err == nil {
		t.Fatal("send must error when pending stays full past the stall timeout")
	}
	if inner.sent != 1 {
		t.Fatalf("stalled message must not reach the wire, sent=%d", inner.sent)
	}

	var drained int
	if derr := a.ring.Drain(func([]byte) error { drained++; return nil }); derr != nil {
		t.Fatalf("drain: %v", derr)
	}
	if drained != 1 {
		t.Fatalf("stalled message must be spooled for replay, drained=%d", drained)
	}
}

func TestDrainTracksReplayedRecords(t *testing.T) {
	ringPath := filepath.Join(t.TempDir(), "buf.jsonl")
	a := &Agent{
		ring:         buffer.New(ringPath, 1<<20, 0),
		pending:      map[uint64][]byte{},
		pendingFreed: make(chan struct{}, 1),
	}
	for i := 0; i < 3; i++ {
		msg, err := protocol.Encode(protocol.TypeHeartbeat, 0, protocol.Heartbeat{ServerID: "x", Timestamp: int64(1000 + i)})
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(msg)
		if err := a.ring.Append(raw); err != nil {
			t.Fatal(err)
		}
	}

	inner := &stubConn{}
	a.drainSpool(&trackedConn{inner: inner, a: a})
	if inner.sent != 3 {
		t.Fatalf("replay must reach the wire, sent=%d", inner.sent)
	}
	a.pmu.Lock()
	tracked := len(a.pending)
	a.pmu.Unlock()
	if tracked != 3 {
		t.Fatalf("replayed spool records must be TRACKED (fresh seqs) so an unacked replay re-spools on disconnect, pending=%d", tracked)
	}

	a.spoolPending()
	drained := 0
	if err := a.ring.Drain(func([]byte) error { drained++; return nil }); err != nil {
		t.Fatal(err)
	}
	if drained != 3 {
		t.Fatalf("an unacked replay must survive the disconnect back into the spool, got %d", drained)
	}
}

func TestUntrackedSeqZeroBypassesBackpressure(t *testing.T) {
	oldCap := pendingCap
	pendingCap = 1
	defer func() { pendingCap = oldCap }()

	a := &Agent{pending: map[uint64][]byte{}, pendingFreed: make(chan struct{}, 1)}
	inner := &stubConn{}
	tc := &trackedConn{inner: inner, a: a}
	a.pending[99] = []byte("x")

	done := make(chan error, 1)
	go func() { done <- tc.Send(protocol.Message{Seq: 0, Type: protocol.TypeMetrics}) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("seq=0 send: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("seq=0 (spool replay) message must not be gated by backpressure")
	}
}
