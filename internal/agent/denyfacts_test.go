package agent

import (
	"testing"

	"wakora.io/agent/internal/protocol"
)

func TestDropServiceFactsRetractsWhatTheServiceOwned(t *testing.T) {
	a := &Agent{
		serviceFacts: map[string]map[string]string{
			"mysql": {"version": "10.11"},
			"nginx": {"version": "1.24"},
		},
		probeFacts: map[string][]protocol.Fact{
			"mysql/vars":   {{Kind: "service", Key: "mysql"}},
			"mysql/tcp":    {{Kind: "service", Key: "mysql"}},
			"nginx/vhosts": {{Kind: "vhost", Key: "example.com:443"}},
		},
	}
	if !a.dropServiceFacts("mysql") {
		t.Fatal("dropping a switched-off service reported no change")
	}
	if _, ok := a.serviceFacts["mysql"]; ok {
		t.Fatal("the service facts survived")
	}
	if _, ok := a.probeFacts["mysql/vars"]; ok {
		t.Fatal("a probe of the switched-off service kept its inventory")
	}
	if _, ok := a.probeFacts["mysql/tcp"]; ok {
		t.Fatal("a second probe of the switched-off service kept its inventory")
	}
	if _, ok := a.serviceFacts["nginx"]; !ok {
		t.Fatal("a neighbouring service lost its facts")
	}
	if _, ok := a.probeFacts["nginx/vhosts"]; !ok {
		t.Fatal("a neighbouring probe lost its inventory")
	}
}

func TestDropServiceFactsIsIdempotent(t *testing.T) {
	a := &Agent{
		serviceFacts: map[string]map[string]string{"mysql": {"version": "10.11"}},
		probeFacts:   map[string][]protocol.Fact{"mysql/vars": {{Kind: "service", Key: "mysql"}}},
	}
	if !a.dropServiceFacts("mysql") {
		t.Fatal("the first drop reported no change")
	}
	if a.dropServiceFacts("mysql") {
		t.Fatal("the second drop reported a change and would re-send discovery every cycle")
	}
}

func TestDropServiceFactsLeavesAPrefixNeighbourAlone(t *testing.T) {
	a := &Agent{
		serviceFacts: map[string]map[string]string{"mysql-router": {"version": "8.0"}},
		probeFacts:   map[string][]protocol.Fact{"mysql-router/tcp": {{Kind: "service", Key: "mysql-router"}}},
	}
	if a.dropServiceFacts("mysql") {
		t.Fatal("a service whose name only shares a prefix was retracted")
	}
}
