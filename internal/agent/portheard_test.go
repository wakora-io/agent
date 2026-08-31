package agent

import (
	"testing"

	"wakora.io/agent/internal/discovery"
)

func TestPortHeardFindsAListener(t *testing.T) {
	a := &Agent{facts: []discovery.Fact{
		{Kind: "port", Key: "22/tcp", Payload: `{"process":"systemd","pid":1}`},
		{Kind: "port", Key: "25/tcp", Payload: `{"process":"master","pid":621}`},
	}}
	if !a.portHeard("22") {
		t.Fatal("a port held by systemd must still count as heard")
	}
}

func TestPortHeardRejectsAConfiguredPortNobodyListensOn(t *testing.T) {
	a := &Agent{facts: []discovery.Fact{
		{Kind: "port", Key: "22/tcp", Payload: `{"process":"systemd","pid":1}`},
	}}
	if a.portHeard("22000") {
		t.Fatal("a port absent from the listener set must not be reported as heard")
	}
}

func TestPortHeardTrustsTheConfigWhenPortsAreUndiscovered(t *testing.T) {
	a := &Agent{facts: []discovery.Fact{
		{Kind: "process", Key: "sshd", Payload: `{"pid":700}`},
	}}
	if !a.portHeard("22000") {
		t.Fatal("without any port facts the agent must not second-guess the config")
	}
}
