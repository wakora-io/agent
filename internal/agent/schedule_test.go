package agent

import (
	"testing"
	"time"

	"wakora.io/agent/internal/protocol"
)

func TestSelectDueProbesPerProbeInterval(t *testing.T) {
	active := []protocol.Definition{{
		Service:     "nginx",
		IntervalSec: 60,
		Probes: []protocol.Probe{
			{Name: "http", Type: "http"},
			{Name: "vhosts", Type: "vhosts", IntervalSec: 300},
		},
	}}
	lastRun := map[string]time.Time{}
	start := time.Now()

	due := selectDueProbes(active, lastRun, start)
	if len(due) != 1 || len(due[0].probes) != 2 {
		t.Fatalf("first tick must run both probes, got %+v", due)
	}

	due = selectDueProbes(active, lastRun, start.Add(70*time.Second))
	if len(due) != 1 || len(due[0].probes) != 1 || due[0].probes[0].Name != "http" {
		t.Fatalf("at +70s only http is due, got %+v", due)
	}

	due = selectDueProbes(active, lastRun, start.Add(100*time.Second))
	if len(due) != 0 {
		t.Fatalf("at +100s nothing is due, got %+v", due)
	}

	due = selectDueProbes(active, lastRun, start.Add(380*time.Second))
	if len(due) != 1 || len(due[0].probes) != 2 {
		t.Fatalf("at +380s both are due again, got %+v", due)
	}
}

func TestSelectDueProbesKeepsSameNamedProbesOfOneServiceApart(t *testing.T) {
	active := []protocol.Definition{
		{Service: "vsftpd", IntervalSec: 60, Probes: []protocol.Probe{{Name: "xfer", Type: "logtail"}}},
		{Service: "vsftpd", IntervalSec: 30, Probes: []protocol.Probe{{Name: "xfer", Type: "logs"}}},
	}
	lastRun := map[string]time.Time{}
	start := time.Now()
	due := selectDueProbes(active, lastRun, start)
	if len(due) != 2 {
		t.Fatalf("both definitions must run their own probe, got %+v", due)
	}
	types := map[string]bool{}
	for _, r := range due {
		for _, p := range r.probes {
			types[p.Type] = true
		}
	}
	if !types["logtail"] || !types["logs"] {
		t.Fatalf("one probe silenced the other: %+v", types)
	}
}

func TestSelectDueProbesDefaultInterval(t *testing.T) {
	active := []protocol.Definition{{
		Service: "plain",
		Probes:  []protocol.Probe{{Name: "tcp", Type: "tcp"}},
	}}
	lastRun := map[string]time.Time{}
	start := time.Now()

	if due := selectDueProbes(active, lastRun, start); len(due) != 1 {
		t.Fatalf("first tick must be due, got %+v", due)
	}
	if due := selectDueProbes(active, lastRun, start.Add(30*time.Second)); len(due) != 0 {
		t.Fatalf("default interval is a minute, got %+v", due)
	}
	if due := selectDueProbes(active, lastRun, start.Add(61*time.Second)); len(due) != 1 {
		t.Fatalf("due after a minute, got %+v", due)
	}
}
