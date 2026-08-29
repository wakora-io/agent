package agent

import (
	"testing"

	"wakora.io/agent/internal/protocol"
)

func TestTailConfigSigStableAndOrderIndependent(t *testing.T) {
	defsA := []protocol.Definition{
		{Service: "nginx", Probes: []protocol.Probe{{Name: "log", Type: "logs", PathFrom: "accessLog"}}},
		{Service: "postfix", Probes: []protocol.Probe{{Name: "maillog", Type: "logs"}}},
	}
	defsB := []protocol.Definition{
		{Service: "postfix", Probes: []protocol.Probe{{Name: "maillog", Type: "logs"}}},
		{Service: "nginx", Probes: []protocol.Probe{{Name: "log", Type: "logs", PathFrom: "accessLog"}}},
	}
	deny := map[string]bool{"logs": false}
	denySvc := map[string]bool{}
	logDeep := map[string]bool{}

	s1 := tailConfigSig(defsA, deny, denySvc, logDeep)
	s2 := tailConfigSig(defsB, deny, denySvc, logDeep)
	if s1 != s2 {
		t.Fatal("definition order must not change the signature (roles/liveness churn must not wipe the fd cache)")
	}
	if tailConfigSig(defsA, deny, denySvc, logDeep) != s1 {
		t.Fatal("identical input must produce an identical signature")
	}
}

func TestTailConfigSigDetectsRealChanges(t *testing.T) {
	base := []protocol.Definition{
		{Service: "nginx", Probes: []protocol.Probe{{Name: "log", Type: "logs", PathFrom: "accessLog"}}},
	}
	empty := map[string]bool{}
	sig := tailConfigSig(base, empty, empty, empty)

	if tailConfigSig(base, map[string]bool{"logs": true}, empty, empty) == sig {
		t.Fatal("a logs deny change must change the signature")
	}
	if tailConfigSig(base, empty, map[string]bool{"nginx": true}, empty) == sig {
		t.Fatal("a service deny change must change the signature")
	}
	if tailConfigSig(base, empty, empty, map[string]bool{"nginx": true}) == sig {
		t.Fatal("a logDeep change must change the signature (it re-arms file reads)")
	}
	changed := []protocol.Definition{
		{Service: "nginx", Probes: []protocol.Probe{{Name: "log", Type: "logs", PathFrom: "errorLog"}}},
	}
	if tailConfigSig(changed, empty, empty, empty) == sig {
		t.Fatal("a changed tail path must change the signature")
	}
}
