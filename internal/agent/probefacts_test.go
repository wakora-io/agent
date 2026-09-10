package agent

import (
	"testing"
	"time"

	"wakora.io/agent/internal/protocol"
)

func TestProbeFactsSurviveShortFailures(t *testing.T) {
	a := &Agent{probeFacts: map[string][]protocol.Fact{"device_192_0_2_3/snmp": {{Kind: "link", Key: "192.0.2.3|ether1|aa:bb:cc:dd:ee:01"}}}}
	t0 := time.Date(2026, 9, 4, 19, 25, 0, 0, time.UTC)
	for _, dt := range []time.Duration{0, time.Minute, time.Hour, 23*time.Hour + 59*time.Minute} {
		if !a.probeFactsHeld("device_192_0_2_3/snmp", t0.Add(dt)) {
			t.Fatalf("facts must be held %s into the failure", dt)
		}
	}
	if _, ok := a.probeFacts["device_192_0_2_3/snmp"]; !ok {
		t.Fatal("holding must not touch the facts")
	}
}

func TestProbeFactsRetractAfterTheHold(t *testing.T) {
	a := &Agent{probeFacts: map[string][]protocol.Fact{"device_192_0_2_3/snmp": {{Kind: "link", Key: "192.0.2.3|ether1|aa:bb:cc:dd:ee:01"}}}}
	t0 := time.Date(2026, 9, 4, 19, 25, 0, 0, time.UTC)
	a.probeFactsHeld("device_192_0_2_3/snmp", t0)
	if a.probeFactsHeld("device_192_0_2_3/snmp", t0.Add(probeFactsHold)) {
		t.Fatal("a probe failing for the whole hold releases its facts")
	}
	if !a.setProbeFacts("device_192_0_2_3/snmp", nil) {
		t.Fatal("the retract must report a change so the snapshot ships the tombstones")
	}
	if _, ok := a.probeFacts["device_192_0_2_3/snmp"]; ok {
		t.Fatal("retracted facts must leave the map")
	}
}

func TestProbeRecoveryResetsTheHold(t *testing.T) {
	a := &Agent{probeFacts: map[string][]protocol.Fact{}}
	t0 := time.Date(2026, 9, 4, 19, 25, 0, 0, time.UTC)
	a.probeFactsHeld("nginx/paths", t0)
	a.probeRecovered("nginx/paths")
	if !a.probeFactsHeld("nginx/paths", t0.Add(probeFactsHold+time.Hour)) {
		t.Fatal("a success in between restarts the clock - one late timeout must not retract a working inventory")
	}
}

func TestDropServiceFactsForgetsTheClock(t *testing.T) {
	a := &Agent{
		serviceFacts: map[string]map[string]string{},
		probeFacts:   map[string][]protocol.Fact{"mysql/vars": {{Kind: "service", Key: "mysql"}}},
		probeFailAt:  map[string]time.Time{"mysql/vars": time.Now()},
	}
	if !a.dropServiceFacts("mysql") {
		t.Fatal("dropping a service with facts reports a change")
	}
	if _, ok := a.probeFailAt["mysql/vars"]; ok {
		t.Fatal("the failure clock of a dropped service must go with its facts")
	}
}
