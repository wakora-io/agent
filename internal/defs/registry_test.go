package defs

import (
	"testing"

	"wakora.io/agent/internal/protocol"
)

func TestUnsupportedProbes(t *testing.T) {
	d := protocol.Definition{Service: "x", Probes: []protocol.Probe{
		{Type: "http"}, {Type: "quantum"}, {Type: "snmp"}, {Type: "quantum"},
	}}
	uns := UnsupportedProbes(d)
	if len(uns) != 1 || uns[0] != "quantum" {
		t.Fatalf("expected one unknown type 'quantum', got %v", uns)
	}
	if len(UnsupportedProbes(protocol.Definition{Probes: []protocol.Probe{{Type: "ext"}, {Type: "journal"}}})) != 0 {
		t.Fatal("known types flagged as unsupported")
	}
}
