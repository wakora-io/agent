package agent

import (
	"testing"

	"wakora.io/agent/internal/discovery"
)

func TestListenPortsFromFacts(t *testing.T) {
	got := listenPortsFrom([]discovery.Fact{
		{Kind: "port", Key: "3000/tcp", Payload: `{"addr":"127.0.0.1","pid":42,"process":"node"}`},
		{Kind: "port", Key: "53/udp", Payload: `{"addr":"0.0.0.0","pid":7,"process":"named"}`},
		{Kind: "port", Key: "8080/tcp", Payload: `{"addr":"0.0.0.0"}`},
		{Kind: "process", Key: "node", Payload: `{"pid":42}`},
	})
	if len(got) != 2 {
		t.Fatalf("want the two tcp listeners, got %v", got)
	}
	if lp := got[3000]; lp.Pid != 42 || lp.Process != "node" {
		t.Fatalf("3000/tcp: %+v", lp)
	}
	if _, ok := got[8080]; !ok {
		t.Fatal("a listener without an owner still listens")
	}
	if _, ok := got[53]; ok {
		t.Fatal("udp sockets are not backends")
	}
}
