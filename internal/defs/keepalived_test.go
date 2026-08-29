package defs

import (
	"os"
	"path/filepath"
	"testing"

	"wakora.io/agent/internal/protocol"
)

func TestKeepalivedParsesConfAndVipPresence(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "keepalived.conf")
	os.WriteFile(conf, []byte(`vrrp_instance VI_1 {
    state MASTER
    interface eth0
    virtual_router_id 51
    priority 150
    virtual_ipaddress {
        127.0.0.1/8
    }
}`), 0o644)

	var o Outcome
	runKeepalived(&o, "keepalived", protocol.Probe{Path: conf})
	if o.Check.Status != "ok" {
		t.Fatalf("status: %s (%s)", o.Check.Status, o.Check.Error)
	}
	m := map[string]float64{}
	for _, p := range o.Metrics {
		m[p.Name] = p.Value
	}
	if m["svc.keepalived.priority"] != 150 {
		t.Fatalf("priority: %v", m["svc.keepalived.priority"])
	}
	if m["svc.keepalived.active"] != 1 {
		t.Fatalf("127.0.0.1 is a local addr -> should be active, got %v", m["svc.keepalived.active"])
	}
	if o.Facts["vip"] != "127.0.0.1" || o.Facts["configuredState"] != "MASTER" || o.Facts["vrid"] != "51" {
		t.Fatalf("facts: %+v", o.Facts)
	}
}

func TestKeepalivedNotActiveWhenVipElsewhere(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "k.conf")
	os.WriteFile(conf, []byte("vrrp_instance VI_1 {\n priority 100\n virtual_ipaddress {\n 203.0.113.200/24\n }\n}"), 0o644)
	var o Outcome
	runKeepalived(&o, "keepalived", protocol.Probe{Path: conf})
	for _, p := range o.Metrics {
		if p.Name == "svc.keepalived.active" && p.Value != 0 {
			t.Fatalf("VIP not local -> active must be 0, got %v", p.Value)
		}
	}
}
