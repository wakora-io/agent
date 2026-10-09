package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"wakora.io/agent/internal/config"
	"wakora.io/agent/internal/defs"
	"wakora.io/agent/internal/protocol"
)

type recConn struct{ msgs []protocol.Message }

func (c *recConn) Send(m protocol.Message) error   { c.msgs = append(c.msgs, m); return nil }
func (c *recConn) Recv() (protocol.Message, error) { select {} }
func (c *recConn) Ping(ctx context.Context) error  { return nil }
func (c *recConn) Close() error                    { return nil }

func TestRefusedProbesNeverReachTheirRunners(t *testing.T) {
	old := probeStartSpread
	probeStartSpread = 0
	defer func() { probeStartSpread = old }()

	types := []string{"logtail", "journal", "logs", "traps", "syslog", "netflow", "configfetch",
		"apmprofile", "apmdotnetprofile", "apmnodeprofile", "ebpfhttp", "apmphp", "apmdotnet", "apmnode", "procfact", "exec"}
	var probes []protocol.Probe
	for i, typ := range types {
		probes = append(probes, protocol.Probe{
			Name: typ, Type: typ, Path: "/etc/shadow", Target: "198.51.100.7", Port: 40000 + i,
			Command: "cat", Process: "sshd", Facts: []protocol.ParseRule{{Name: "leak", Regex: "(.+)"}},
			Denied: "refused for the test",
		})
	}
	a := &Agent{
		cfg:       &config.Config{ServerID: "srv", Hostname: "host"},
		active:    []protocol.Definition{{Service: "community_evil", IntervalSec: 60, Probes: probes}},
		lastRun:   map[string]time.Time{},
		probeSeen: map[string]bool{},
		trapL:     map[int]*defs.TrapListener{},
		syslogL:   map[int]*defs.SyslogListener{},
		flowL:     map[int]*defs.FlowListener{},
	}
	c := &recConn{}
	if err := a.runDueProbes(c); err != nil {
		t.Fatal(err)
	}
	if len(c.msgs) != len(types) {
		t.Fatalf("every refused probe must answer with exactly one check, got %d messages for %d probes", len(c.msgs), len(types))
	}
	for _, m := range c.msgs {
		var ch protocol.CheckResult
		if m.Type != protocol.TypeCheck || json.Unmarshal(m.Payload, &ch) != nil {
			t.Fatalf("expected a check, got %s", m.Type)
		}
		if ch.Status != "fail" || ch.Error != "refused for the test" {
			t.Fatalf("probe %s ran instead of answering the refusal: %+v", ch.Kind, ch)
		}
	}
	if len(a.trapL)+len(a.syslogL)+len(a.flowL) != 0 {
		t.Fatal("a refused listener probe opened a port")
	}
	if len(a.serviceFacts) != 0 {
		t.Fatal("a refused probe published facts")
	}
}

func TestOlderConfigGenerationIsIgnored(t *testing.T) {
	a := &Agent{cfg: &config.Config{}}
	a.cfgGen.Store(5)
	payload, _ := json.Marshal(protocol.DefinitionSet{Gen: 3, Deny: []string{"staged"}})
	a.handleDownstream(protocol.Message{Type: protocol.TypeConfig, Payload: payload}, nil, nil, nil)
	if a.cfgGen.Load() != 5 {
		t.Fatal("an older configuration overwrote the newer one it was built before")
	}
}

func TestRefusedListenerIsClosed(t *testing.T) {
	a := &Agent{
		trapL:   map[int]*defs.TrapListener{},
		syslogL: map[int]*defs.SyslogListener{514: defs.NewSyslogListener(514)},
		flowL:   map[int]*defs.FlowListener{},
		active: []protocol.Definition{{Service: "community_evil", Probes: []protocol.Probe{
			{Type: "syslog", Name: "syslog", Denied: "this template runs without the network capability"},
		}}},
	}
	a.closeUnusedListeners()
	if len(a.syslogL) != 0 {
		t.Fatal("a listener of a refused probe stayed open")
	}
}

func TestDeviceTestNeverSendsAServiceSecret(t *testing.T) {
	a := &Agent{
		cfg: &config.Config{},
		defs: []protocol.Definition{
			{Service: "mysql", Probes: []protocol.Probe{{Type: "sql", Name: "status", Secret: "mysql"}}},
			{Service: "linstor-controller", Probes: []protocol.Probe{{Type: "http", Name: "api", SecretOpt: "linstor-controller"}}},
			{Service: "device_192_0_2_1", Probes: []protocol.Probe{{Type: "snmp", Name: "snmp", Secret: "snmp-lab"}}},
		},
	}
	for _, name := range []string{"mysql", "linstor-controller"} {
		res := a.deviceTest(protocol.DevTest{Nonce: "n", Target: "192.0.2.1", Secret: name})
		if res.OK || res.Nonce != "n" || res.Error == "" || !strings.Contains(res.Error, "never sent to a device") {
			t.Fatalf("secret %s reached a device test: %+v", name, res)
		}
	}
	if defs.ServiceSecret(a.defs, "snmp-lab") || defs.ServiceSecret(a.defs, "") || defs.ServiceSecret(a.defs, "new-cred") {
		t.Fatal("a device or new credential was taken for a service secret")
	}
}
