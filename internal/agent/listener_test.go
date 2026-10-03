package agent

import (
	"testing"

	"wakora.io/agent/internal/defs"
	"wakora.io/agent/internal/protocol"
)

func TestListenerOnAMovedPortIsClosed(t *testing.T) {
	a := &Agent{
		trapL:   map[int]*defs.TrapListener{162: defs.NewTrapListener(162)},
		syslogL: map[int]*defs.SyslogListener{514: defs.NewSyslogListener(514), 5514: defs.NewSyslogListener(5514)},
		flowL:   map[int]*defs.FlowListener{2055: defs.NewFlowListener(2055)},
		active: []protocol.Definition{{Service: "site", Probes: []protocol.Probe{
			{Type: "syslog", Name: "syslog", Port: 5514},
			{Type: "netflow", Name: "flows"},
		}}},
	}
	a.closeUnusedListeners()
	if _, ok := a.syslogL[514]; ok {
		t.Fatal("the syslog listener on the old port survived")
	}
	if _, ok := a.syslogL[5514]; !ok {
		t.Fatal("the syslog listener on the current port was closed")
	}
	if _, ok := a.trapL[162]; ok {
		t.Fatal("a trap listener no definition uses survived")
	}
	if _, ok := a.flowL[2055]; !ok {
		t.Fatal("the netflow listener on its default port was closed")
	}
}

func TestDeniedServiceReleasesItsListener(t *testing.T) {
	a := &Agent{
		trapL:   map[int]*defs.TrapListener{},
		syslogL: map[int]*defs.SyslogListener{514: defs.NewSyslogListener(514)},
		flowL:   map[int]*defs.FlowListener{},
		denySvc: map[string]bool{"site": true},
		active:  []protocol.Definition{{Service: "site", Probes: []protocol.Probe{{Type: "syslog", Name: "syslog"}}}},
	}
	a.closeUnusedListeners()
	if len(a.syslogL) != 0 {
		t.Fatal("a listener of a service the console switched off stayed open")
	}
}
