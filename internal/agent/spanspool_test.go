package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wakora.io/agent/internal/buffer"
	"wakora.io/agent/internal/config"
	"wakora.io/agent/internal/protocol"
)

const spoolTestExport = `{"resourceSpans":[{"resource":{"attributes":[
	{"key":"service.name","value":{"stringValue":"shop"}}
]},"scopeSpans":[{"spans":[
	{"traceId":"t1","spanId":"s1","name":"GET /","kind":2,
	 "startTimeUnixNano":"100","endTimeUnixNano":"200","status":{}}
]}]}]}`

func postSpans(a *Agent) int {
	req := httptest.NewRequest(http.MethodPost, "/v1/traces", strings.NewReader(spoolTestExport))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	a.handleOTLPTraces(rec, req)
	return rec.Code
}

func TestOTLPSpansSpoolWhileTheLinkIsDown(t *testing.T) {
	a := &Agent{
		cfg:          &config.Config{ServerID: "srv", Hostname: "host"},
		spans:        make(chan []protocol.Span),
		spanRing:     buffer.New(filepath.Join(t.TempDir(), "spans.jsonl"), 1<<20, 0),
		pending:      map[uint64][]byte{},
		pendingFreed: make(chan struct{}, 1),
	}
	for i := 0; i < 3; i++ {
		if code := postSpans(a); code != http.StatusOK {
			t.Fatalf("export %d answered %d, the application must see an accepted export", i, code)
		}
	}
	inner := &stubConn{}
	a.drainSpans(&trackedConn{inner: inner, a: a})
	if inner.sent != 3 {
		t.Fatalf("spooled exports must replay on the link, sent=%d", inner.sent)
	}
	if a.spanRing.Size() != 0 {
		t.Fatal("the span spool must be empty after a full replay")
	}
	a.pmu.Lock()
	tracked := len(a.pending)
	a.pmu.Unlock()
	if tracked != 3 {
		t.Fatalf("replayed span batches must be tracked for acks, pending=%d", tracked)
	}
}

func TestOTLPWithoutSpanSpoolStillRefuses(t *testing.T) {
	a := &Agent{cfg: &config.Config{}, spans: make(chan []protocol.Span)}
	if code := postSpans(a); code != http.StatusTooManyRequests {
		t.Fatalf("no spool and no reader must answer 429, got %d", code)
	}
}

func TestSpanSpoolDropsOldestPastItsCap(t *testing.T) {
	ring := buffer.New(filepath.Join(t.TempDir(), "spans.jsonl"), 4<<10, 0)
	a := &Agent{cfg: &config.Config{ServerID: "srv"}, spans: make(chan []protocol.Span), spanRing: ring}
	for i := 0; i < 200; i++ {
		postSpans(a)
	}
	if ring.Size() > 4<<10 {
		t.Fatalf("span spool grew past its cap: %d bytes", ring.Size())
	}
	n := 0
	_ = ring.Drain(func(line []byte) error {
		var m protocol.Message
		if json.Unmarshal(line, &m) == nil && m.Type == protocol.TypeSpans {
			n++
		}
		return nil
	})
	if n == 0 {
		t.Fatal("the newest exports must survive the trim")
	}
}

func TestFirstProbeRunsAreSpreadNotImmediate(t *testing.T) {
	active := []protocol.Definition{{
		Service:     "nginx",
		IntervalSec: 60,
		Probes: []protocol.Probe{
			{Name: "http", Type: "http"},
			{Name: "fast", Type: "tcp", IntervalSec: 15},
		},
	}}
	lastRun := map[string]time.Time{}
	seen := map[string]bool{}
	start := time.Unix(1_000_000, 0)
	pick := func(w time.Duration) time.Duration { return w - time.Second }

	spreadFirstRuns(active, lastRun, seen, start, time.Minute, pick)
	if due := selectDueProbes(active, lastRun, start); len(due) != 0 {
		t.Fatalf("no probe may fire at the very first tick, got %+v", due)
	}
	due := selectDueProbes(active, lastRun, start.Add(14*time.Second))
	if len(due) != 1 || len(due[0].probes) != 1 || due[0].probes[0].Name != "fast" {
		t.Fatalf("the 15s probe is spread inside its own interval, got %+v", due)
	}
	due = selectDueProbes(active, lastRun, start.Add(59*time.Second))
	if len(due) != 1 || due[0].probes[0].Name != "http" {
		t.Fatalf("the minute probe fires within the first minute, got %+v", due)
	}
}

func TestDefinitionChangeStillRerunsImmediately(t *testing.T) {
	active := []protocol.Definition{{Service: "cfg", IntervalSec: 86400, Probes: []protocol.Probe{{Name: "fetch", Type: "configfetch"}}}}
	lastRun := map[string]time.Time{}
	seen := map[string]bool{}
	start := time.Unix(1_000_000, 0)
	spreadFirstRuns(active, lastRun, seen, start, time.Minute, func(w time.Duration) time.Duration { return w / 2 })
	delete(lastRun, probeKey(active[0], active[0].Probes[0]))
	spreadFirstRuns(active, lastRun, seen, start.Add(time.Hour), time.Minute, func(w time.Duration) time.Duration { return w / 2 })
	if due := selectDueProbes(active, lastRun, start.Add(time.Hour)); len(due) != 1 {
		t.Fatalf("a probe whose timer was reset by a definition change must run at once, got %+v", due)
	}
}
