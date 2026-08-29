package defs

import (
	"testing"

	"github.com/gosnmp/gosnmp"

	"wakora.io/agent/internal/protocol"
	"wakora.io/agent/internal/secret"
)

func credFixture(user, pass, priv string) secret.Cred {
	return secret.Cred{User: user, Pass: pass, Priv: priv}
}

func TestTrapListenerAllowFilter(t *testing.T) {
	l := NewTrapListener(0)
	l.SetAllowed([]string{"192.0.2.87"})

	packet := &gosnmp.SnmpPacket{
		Version: gosnmp.Version2c,
		Variables: []gosnmp.SnmpPDU{
			{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(1000)},
			{Name: ".1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.6.3.1.1.5.3"},
			{Name: ".1.3.6.1.2.1.2.2.1.1.2", Type: gosnmp.Integer, Value: 2},
		},
	}
	l.ingest("192.0.2.87", packet)
	l.ingest("10.6.6.6", packet)

	events, total, dropped, _ := l.Drain()
	if total != 1 || dropped != 1 {
		t.Fatalf("total=%d dropped=%d, want 1/1 (spoofed source must be dropped)", total, dropped)
	}
	if len(events) != 1 {
		t.Fatalf("events=%d, want 1", len(events))
	}
	ev := events[0]
	if ev.Name != "linkDown" || ev.OID != "1.3.6.1.6.3.1.1.5.3" || ev.Source != "192.0.2.87" {
		t.Fatalf("event parse wrong: %+v", ev)
	}
	if events, _, _, _ := l.Drain(); len(events) != 0 {
		t.Fatal("drain must clear buffered events")
	}
}

func TestTrapBufferCap(t *testing.T) {
	l := NewTrapListener(0)
	l.SetAllowed([]string{"192.0.2.1"})
	p := &gosnmp.SnmpPacket{Version: gosnmp.Version2c}
	for i := 0; i < trapEventCap+50; i++ {
		l.ingest("192.0.2.1", p)
	}
	events, total, _, _ := l.Drain()
	if len(events) != trapEventCap {
		t.Fatalf("buffer must cap at %d, got %d", trapEventCap, len(events))
	}
	if total != uint64(trapEventCap+50) {
		t.Fatalf("total must count all accepted, got %d", total)
	}
}

func TestSyslogSeverityAndCounters(t *testing.T) {
	l := NewSyslogListener(0)
	l.Configure([]protocol.Counter{{Name: "dev.syslog.link_rate", Regex: "link (up|down)"}}, nil)

	l.ingest("192.0.2.23", "<3>Jul  3 00:00:01 sw1 port: link down on ether5")
	l.ingest("192.0.2.23", "<14>Jul  3 00:00:02 sw1 info: link up on ether5")
	l.ingest("192.0.2.23", "<14>Jul  3 00:00:03 sw1 dhcp lease")
	l.ingest("192.0.2.23", "no pri header at all")

	total, severe, dropped, matches, _ := l.Snapshot()
	if total != 4 || dropped != 0 {
		t.Fatalf("total=%d dropped=%d, want 4/0", total, dropped)
	}
	if severe != 1 {
		t.Fatalf("severe=%d, want 1 (only <3> err line)", severe)
	}
	if matches["dev.syslog.link_rate"] != 2 {
		t.Fatalf("link counter=%d, want 2", matches["dev.syslog.link_rate"])
	}
}

func TestSyslogAllowFilter(t *testing.T) {
	l := NewSyslogListener(0)
	l.Configure(nil, []string{"192.0.2.87"})
	l.ingest("192.0.2.87", "<14>ok")
	l.ingest("10.6.6.6", "<14>spoof")
	total, _, dropped, _, _ := l.Snapshot()
	if total != 1 || dropped != 1 {
		t.Fatalf("total=%d dropped=%d, want 1/1", total, dropped)
	}
}

func TestSNMPv3Params(t *testing.T) {
	g := &gosnmp.GoSNMP{}
	err := snmpV3(g, protocol.Probe{V3: true, AuthProto: "SHA", PrivProto: "AES"},
		credFixture("mon", "authpass", "privpass"))
	if err != nil {
		t.Fatal(err)
	}
	if g.Version != gosnmp.Version3 || g.MsgFlags != gosnmp.AuthPriv {
		t.Fatalf("want v3 AuthPriv, got %v %v", g.Version, g.MsgFlags)
	}
	usm := g.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	if usm.UserName != "mon" || usm.AuthenticationProtocol != gosnmp.SHA || usm.PrivacyProtocol != gosnmp.AES {
		t.Fatalf("usm wrong: %+v", usm)
	}

	if err := snmpV3(&gosnmp.GoSNMP{}, protocol.Probe{V3: true, AuthProto: "SHA", PrivProto: "AES"},
		credFixture("mon", "authpass", "")); err == nil {
		t.Fatal("missing priv passphrase must fail")
	}
	if err := snmpV3(&gosnmp.GoSNMP{}, protocol.Probe{V3: true, AuthProto: "WHIRLPOOL"},
		credFixture("mon", "x", "")); err == nil {
		t.Fatal("unknown auth proto must fail")
	}

	g2 := &gosnmp.GoSNMP{}
	if err := snmpV3(g2, protocol.Probe{V3: true, AuthProto: "SHA"}, credFixture("mon", "authpass", "")); err != nil {
		t.Fatal(err)
	}
	if g2.MsgFlags != gosnmp.AuthNoPriv {
		t.Fatalf("want AuthNoPriv without privProto, got %v", g2.MsgFlags)
	}
}

func TestSyslogSeverityParse(t *testing.T) {
	cases := map[string]struct {
		sev int
		ok  bool
	}{
		"<3>err line":    {3, true},
		"<165>notice":    {5, true},
		"<999>bogus":     {0, false},
		"no header":      {0, false},
		"<>empty":        {0, false},
		"<14>info clean": {6, true},
	}
	for line, want := range cases {
		sev, ok := syslogSeverity(line)
		if ok != want.ok || (ok && sev != want.sev) {
			t.Fatalf("syslogSeverity(%q) = %d,%v want %d,%v", line, sev, ok, want.sev, want.ok)
		}
	}
}
