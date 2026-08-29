package defs

import (
	"strings"
	"testing"

	"wakora.io/agent/internal/protocol"
)

func TestRecoverProbeMarksFailAndClears(t *testing.T) {
	o := Outcome{
		Check:    protocol.CheckResult{CheckID: "svc/probe", Status: "ok"},
		Metrics:  []protocol.MetricPoint{{Name: "svc.x", Value: 1}},
		InvFacts: []protocol.Fact{{Kind: "device", Key: "h"}},
	}
	recoverProbe(&o, "boom")
	if o.Check.Status != "fail" {
		t.Fatalf("status = %q, want fail", o.Check.Status)
	}
	if !strings.Contains(o.Check.Error, "boom") {
		t.Fatalf("error = %q, want it to mention the panic value", o.Check.Error)
	}
	if o.Metrics != nil || o.InvFacts != nil {
		t.Fatal("partial metrics/facts must be dropped on panic")
	}
}

func TestRunProbeRecoversFromPanic(t *testing.T) {
	o := runProbePanicHarness()
	if o.Check.Status != "fail" {
		t.Fatalf("panicking probe should return fail, got %q", o.Check.Status)
	}
	if !strings.Contains(o.Check.Error, "panicked") {
		t.Fatalf("error = %q, want it to record the panic", o.Check.Error)
	}
}

func runProbePanicHarness() (o Outcome) {
	o = Outcome{Check: protocol.CheckResult{CheckID: "svc/panic"}}
	defer func() {
		if r := recover(); r != nil {
			recoverProbe(&o, r)
		}
	}()
	panic("simulated probe panic")
}
