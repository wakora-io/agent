package transport

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestBackoffGrowsToCeiling(t *testing.T) {
	base, ceiling := time.Second, 30*time.Second
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second}
	cur := time.Duration(0)
	for i, w := range want {
		cur = nextBackoff(cur, base, ceiling)
		if cur != w {
			t.Fatalf("step %d: got %v want %v", i, cur, w)
		}
	}
}

func TestJitterStaysInUpperHalf(t *testing.T) {
	d := 10 * time.Second
	for i := 0; i < 1000; i++ {
		j := jittered(d)
		if j < d/2 || j > d {
			t.Fatalf("jitter %v outside [%v, %v]", j, d/2, d)
		}
	}
}

type failDialer struct {
	mu    sync.Mutex
	times []time.Time
}

func (f *failDialer) Dial(ctx context.Context, endpoint string) (Conn, error) {
	f.mu.Lock()
	f.times = append(f.times, time.Now())
	f.mu.Unlock()
	return nil, errors.New("refused")
}

func TestRunBacksOffBetweenFailedDials(t *testing.T) {
	d := &failDialer{}
	c := &Client{Endpoint: "wss://example.com/ws", Dialer: d, Backoff: 20 * time.Millisecond, MaxBackoff: 80 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	_ = c.Run(ctx, func(Conn) error { return nil })
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.times) < 4 {
		t.Fatalf("only %d dials in 400ms", len(d.times))
	}
	if len(d.times) > 14 {
		t.Fatalf("%d dials in 400ms - backoff is not growing", len(d.times))
	}
	last := d.times[len(d.times)-1].Sub(d.times[len(d.times)-2])
	if last < 35*time.Millisecond {
		t.Fatalf("late gap %v, want at least half the ceiling", last)
	}
}
