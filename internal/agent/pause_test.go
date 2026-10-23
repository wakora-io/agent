package agent

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"wakora.io/agent/internal/anomaly"
	"wakora.io/agent/internal/buffer"
	"wakora.io/agent/internal/config"
	"wakora.io/agent/internal/pause"
	"wakora.io/agent/internal/protocol"
)

func pausedAgent(t *testing.T) (*Agent, string) {
	t.Helper()
	dir := t.TempDir()
	old := pauseStateDir
	pauseStateDir = func(*config.Config) string { return dir }
	t.Cleanup(func() { pauseStateDir = old })
	a := &Agent{
		cfg:       &config.Config{ServerID: "srv", Hostname: "host"},
		detector:  anomaly.New(),
		lastRun:   map[string]time.Time{"web/http/home": time.Now()},
		probeSeen: map[string]bool{"web/http/home": true},
		spans:     make(chan []protocol.Span, 4),
		custom:    make(chan []protocol.MetricPoint, 4),
	}
	a.rumAllowed.Store(map[string]bool{})
	a.paused.Store("")
	return a, dir
}

func pushConfig(a *Agent, set protocol.DefinitionSet, dkick chan struct{}) {
	payload, _ := json.Marshal(set)
	a.handleDownstream(protocol.Message{Type: protocol.TypeConfig, Payload: payload}, nil, dkick, nil)
}

func TestPausedConfigStopsCollectingAndPersists(t *testing.T) {
	a, dir := pausedAgent(t)
	a.defs = []protocol.Definition{{Service: "web"}}
	a.roles = map[string]string{"device_192_0_2_1": "host"}

	pushConfig(a, protocol.DefinitionSet{Paused: "unpaid", Roles: map[string]string{"device_192_0_2_1": "host"}}, nil)
	if a.Paused() != pause.Unpaid {
		t.Fatalf("got %q", a.Paused())
	}
	if len(a.defs) != 0 || len(a.roles) != 0 {
		t.Fatal("a paused host must hold no definition and no collector role")
	}
	if len(a.lastRun) != 0 || len(a.probeSeen) != 0 {
		t.Fatal("entering the pause must forget probe timers so the return spreads its first runs")
	}
	if pause.Read(dir) != pause.Unpaid {
		t.Fatal("the pause must survive a restart")
	}

	dkick := make(chan struct{}, 1)
	pushConfig(a, protocol.DefinitionSet{}, dkick)
	if a.Paused() != "" {
		t.Fatal("a config without the pause must lift it")
	}
	if pause.Read(dir) != "" {
		t.Fatal("lifting the pause must clear it on disk")
	}
	select {
	case <-dkick:
	default:
		t.Fatal("lifting the pause must start a discovery at once")
	}
}

func TestPausedAgentStartsPausedFromDisk(t *testing.T) {
	dir := t.TempDir()
	old := pauseStateDir
	pauseStateDir = func(*config.Config) string { return dir }
	defer func() { pauseStateDir = old }()
	if err := pause.Write(dir, pause.Plan); err != nil {
		t.Fatal(err)
	}
	a := New(&config.Config{}, buffer.New(dir+"/ring.jsonl", 1<<20, time.Hour), "")
	if a.Paused() != pause.Plan {
		t.Fatalf("a restarted agent must come back paused, got %q", a.Paused())
	}
}

func TestPausedAgentRefusesDeviceTests(t *testing.T) {
	a, _ := pausedAgent(t)
	a.paused.Store(pause.Plan)
	res := a.deviceTest(protocol.DevTest{Nonce: "n", Target: "192.0.2.1", Secret: "snmp-lab"})
	if res.OK || res.Nonce != "n" || res.Error == "" {
		t.Fatalf("a paused collector must refuse device tests, got %+v", res)
	}
}

func TestPausedReceiversAcceptAndDrop(t *testing.T) {
	a, _ := pausedAgent(t)
	a.paused.Store(pause.Unpaid)
	body := `{"resourceSpans":[{"scopeSpans":[{"spans":[{"traceId":"0102030405060708090a0b0c0d0e0f10","spanId":"0102030405060708","name":"GET /","kind":2,"startTimeUnixNano":"100","endTimeUnixNano":"200","status":{}}]}]}]}`
	w := httptest.NewRecorder()
	a.handleOTLPTraces(w, httptest.NewRequest(http.MethodPost, "/v1/traces", bytes.NewBufferString(body)))
	if w.Code != http.StatusOK {
		t.Fatalf("the exporter must see success while paused, got %d", w.Code)
	}
	if len(a.spans) != 0 {
		t.Fatal("a paused agent must not forward spans")
	}
	w = httptest.NewRecorder()
	a.handleCustomIngest(w, httptest.NewRequest(http.MethodPost, "/ingest", bytes.NewBufferString(`{"name":"app.orders","value":3}`)))
	if w.Code != http.StatusAccepted || len(a.custom) != 0 {
		t.Fatalf("a paused agent must accept and drop app metrics, got %d with %d queued", w.Code, len(a.custom))
	}
}
