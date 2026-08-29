package defs

import (
	"net"
	"strings"
	"testing"
	"time"

	"wakora.io/agent/internal/protocol"
)

func TestSNMPFailsFastOnSilentTarget(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	p := protocol.Probe{
		Name: "snmp", Type: "snmp", Target: pc.LocalAddr().String(), TimeoutSec: 1,
		Get:  []protocol.OID{{Name: "dev.sys.uptime", OID: "1.3.6.1.2.1.1.3.0"}},
		Walk: []protocol.OID{{Name: "dev.if.in_octets", OID: "1.3.6.1.2.1.31.1.1.1.6"}},
	}
	start := time.Now()
	o := RunProbe("dead-device", p)
	elapsed := time.Since(start)

	if o.Check.Status != "fail" {
		t.Fatalf("silent target must fail, got %q", o.Check.Status)
	}
	if !strings.Contains(o.Check.Error, "did not answer") {
		t.Fatalf("fail-fast verdict expected, got %q", o.Check.Error)
	}
	if len(o.Metrics) != 0 {
		t.Fatalf("no metrics from a dead target, got %d", len(o.Metrics))
	}
	if elapsed > 3*time.Second {
		t.Fatalf("the liveness preflight must bound a dead target to one short get, took %v", elapsed)
	}
}
