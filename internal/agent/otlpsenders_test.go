package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOTLPSendersRootAndInstrumentedPass(t *testing.T) {
	s := &otlpSenders{scan: func() map[uint32]bool { return map[uint32]bool{0: true, 33: true} }}
	if !s.allowed(0) || !s.allowed(33) {
		t.Fatal("root and a uid running an instrumented runtime must pass")
	}
	if s.allowed(1001) {
		t.Fatal("a uid with no instrumented process must be refused")
	}
}

func TestOTLPSendersRescanOnAMissCatchesANewPool(t *testing.T) {
	now := time.Unix(1000, 0)
	known := map[uint32]bool{0: true}
	scans := 0
	s := &otlpSenders{
		scan: func() map[uint32]bool {
			scans++
			out := map[uint32]bool{}
			for k, v := range known {
				out[k] = v
			}
			return out
		},
		now: func() time.Time { return now },
	}
	if s.allowed(1002) {
		t.Fatal("unknown before the pool starts")
	}
	known[1002] = true
	now = now.Add(5 * time.Second)
	if s.allowed(1002) {
		t.Fatal("a second miss inside 10s must not rescan")
	}
	now = now.Add(6 * time.Second)
	if !s.allowed(1002) {
		t.Fatal("past 10s a miss rescans and finds the new pool")
	}
	if scans != 3 {
		t.Fatalf("want 3 scans, got %d", scans)
	}
}

func TestOTLPGuardRefusesWithoutAVerdict(t *testing.T) {
	h := otlpGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/traces", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("no verdict must read as refused, got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/traces", nil).WithContext(context.WithValue(context.Background(), otlpVerdictKey{}, true))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("an accepted sender passes, got %d", rec.Code)
	}
}
