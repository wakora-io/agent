package defs

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"wakora.io/agent/internal/protocol"
)

func TestCommunityWithoutCapabilitiesLosesEverythingDangerous(t *testing.T) {
	d := protocol.Definition{
		Service: "community_myapp",
		Probes: []protocol.Probe{
			{Name: "stats", Type: "exec", Command: "systemctl", Args: []string{"stop", "nginx"}},
			{Name: "rows", Type: "sql", Driver: "mysql", Socket: true, User: "root", Query: "SELECT 1"},
			{Name: "conf", Type: "file", Path: "/etc/shadow", Hash: true},
			{Name: "api", Type: "http", URL: "https://collector.example/", Secret: "mysql-monitor", Insecure: true,
				Metrics: []protocol.ParseRule{
					{Name: "svc.mysql.running", Regex: `(\d+)`},
					{Name: "svc.community_myapp.orders", Regex: `(\d+)`},
				}},
		},
	}
	SanitizeTenant(&d)

	for _, i := range []int{0, 1, 2} {
		if d.Probes[i].Denied == "" {
			t.Fatalf("probe %q must be refused without its capability", d.Probes[i].Type)
		}
	}
	api := d.Probes[3]
	if api.Denied != "" {
		t.Fatal("a plain http probe needs no capability")
	}
	if api.Secret != "" || api.Insecure {
		t.Fatal("credentials and tls opt-out must be stripped without the capability")
	}
	if len(api.Metrics) != 1 || api.Metrics[0].Name != "svc.community_myapp.orders" {
		t.Fatalf("only the template's own metric namespace may survive, got %+v", api.Metrics)
	}
}

func TestCommunityWithGrantedCapabilitiesKeepsThem(t *testing.T) {
	d := protocol.Definition{
		Service:      "community_myapp",
		Capabilities: []string{"exec", "creds", "insecure"},
		Probes: []protocol.Probe{
			{Name: "v", Type: "exec", Command: "nginx", Args: []string{"-v"}},
			{Name: "api", Type: "http", URL: "https://localhost:9000/", Secret: "app-monitor", Insecure: true},
			{Name: "rows", Type: "sql", Driver: "mysql", Query: "SELECT 1"},
		},
	}
	SanitizeTenant(&d)

	if d.Probes[0].Denied != "" {
		t.Fatal("exec was granted and must run")
	}
	if d.Probes[1].Secret != "app-monitor" || !d.Probes[1].Insecure {
		t.Fatal("granted creds and insecure must survive")
	}
	if d.Probes[2].Denied == "" {
		t.Fatal("db was NOT granted - the sql probe must still be refused")
	}
}

func TestDeviceDefinitionKeepsItsOwnShape(t *testing.T) {
	d := protocol.Definition{
		Service: "device_192_0_2_10",
		Probes: []protocol.Probe{
			{Name: "snmp", Type: "snmp", Target: "192.0.2.10", Secret: "snmp-device",
				Walk:        []protocol.OID{{Name: "dev.if.in_bps", OID: "1.3.6.1.2.1.31.1.1.1.6"}},
				DeviceFacts: []protocol.OID{{Name: "sysDescr", OID: "1.3.6.1.2.1.1.1.0"}, {Name: "sysObjectID", OID: "1.3.6.1.2.1.1.2.0"}},
				LinkState:   &protocol.LinkState{Oper: "dev.if.oper_status", Out: "dev.if.link_lost"}},
			{Name: "config", Type: "configfetch", Target: "192.0.2.10", Secret: "devssh", Command: "/export"},
		},
	}
	SanitizeTenant(&d)

	if d.Probes[0].Denied != "" || d.Probes[0].Secret != "snmp-device" {
		t.Fatal("an approved device must keep polling with its community string")
	}
	if len(d.Probes[0].Walk) != 1 {
		t.Fatal("dev.* is the device namespace and must survive the metric filter")
	}
	if len(d.Probes[0].DeviceFacts) != 2 {
		t.Fatal("device facts are inventory, not metrics - the metric namespace filter must not touch them")
	}
	if d.Probes[0].LinkState == nil {
		t.Fatal("a link-state rule writing into dev.* must survive")
	}
	if d.Probes[1].Denied != "" || d.Probes[1].Command != "/export" {
		t.Fatal("config backup belongs to devices and must keep running")
	}
}

func TestConfigFetchNeverLeavesTheDeviceNamespace(t *testing.T) {
	d := protocol.Definition{
		Service:      "community_evil",
		Capabilities: []string{"device", "creds"},
		Probes:       []protocol.Probe{{Name: "cfg", Type: "configfetch", Target: "192.0.2.10", Secret: "devssh", Command: "/system reset-configuration"}},
	}
	SanitizeTenant(&d)
	if d.Probes[0].Denied == "" {
		t.Fatal("ssh commands on network gear must stay with console-composed device definitions even when the capability is granted")
	}
}

func TestHostProbesAreNotAvailableToTemplates(t *testing.T) {
	for _, typ := range []string{"docker", "k8s", "pve", "apmphp", "ebpfhttp", "cis", "iis"} {
		d := protocol.Definition{
			Service:      "community_x",
			Capabilities: []string{"creds", "exec", "db", "files", "network", "device", "insecure"},
			Probes:       []protocol.Probe{{Name: "p", Type: typ}},
		}
		SanitizeTenant(&d)
		if d.Probes[0].Denied == "" {
			t.Fatalf("probe type %q must stay with official definitions, no capability buys it", typ)
		}
	}
}

func TestMetricNamespaceHoldsAcrossEveryRuleKind(t *testing.T) {
	d := protocol.Definition{
		Service:      "community_myapp",
		Capabilities: []string{"files", "db", "network"},
		Derived: []protocol.DerivedRule{
			{Name: "svc.mysql.used_pct", Num: "a", Den: "b"},
			{Name: "svc.community_myapp.used_pct", Num: "a", Den: "b"},
		},
		Probes: []protocol.Probe{{
			Name: "tail", Type: "logtail", Path: "/var/log/app.log",
			Counters: []protocol.Counter{
				{Name: "svc.ssh.auth_fail_rate", Regex: "x", Event: "ssh_bruteforce"},
				{Name: "svc.community_myapp.errors", Regex: "y", Event: "ssh_bruteforce"},
			},
			Rates: []protocol.RateRule{
				{Name: "svc.community_myapp.errors", Out: "svc.systemd.oom_kills_rate"},
				{Name: "svc.community_myapp.errors", Out: "svc.community_myapp.errors_rate"},
				{Name: "svc.community_myapp.errors"},
			},
			KVMetrics: []protocol.KVMetric{{Name: "host.cpu.used_pct", Key: "cpu"}},
			Prom:      []protocol.PromRule{{Name: "svc.k8s.nodes_ready", Metric: "n"}},
		}},
	}
	SanitizeTenant(&d)

	p := d.Probes[0]
	if len(p.Counters) != 1 || p.Counters[0].Name != "svc.community_myapp.errors" {
		t.Fatalf("a counter may not carry another service's metric name, got %+v", p.Counters)
	}
	if p.Counters[0].Event != "" {
		t.Fatal("a template may not raise platform events - that is telemetry forgery too")
	}
	if len(p.Rates) != 2 {
		t.Fatalf("only the own-namespace and the default-named rate may survive, got %+v", p.Rates)
	}
	if len(p.KVMetrics) != 0 || len(p.Prom) != 0 {
		t.Fatal("host.* and another service's metrics must go, whatever rule kind names them")
	}
	if len(d.Derived) != 1 || d.Derived[0].Name != "svc.community_myapp.used_pct" {
		t.Fatalf("derived rules follow the same namespace, got %+v", d.Derived)
	}
}

func TestOfficialDefinitionsAreUntouched(t *testing.T) {
	pubPub, pubPriv, _ := ed25519.GenerateKey(rand.Reader)
	official := signDef(t, pubPriv, `{"service":"mysql","match":{"process":"mysqld"},"probes":[{"name":"info","type":"sql","driver":"mysql","socket":true,"user":"root","query":"SHOW GLOBAL STATUS","metrics":[{"name":"svc.mysql.running","regex":"(\\d+)"}]}]}`)
	got := Verify(protocol.DefinitionSet{Definitions: []protocol.SignedDefinition{official}}, base64.StdEncoding.EncodeToString(pubPub), nil)
	if len(got) != 1 {
		t.Fatal("the official definition must verify")
	}
	p := got[0].Probes[0]
	if p.Denied != "" || len(p.Metrics) != 1 {
		t.Fatal("capability sanitising must never touch publisher-signed definitions")
	}
}

func TestVerifySanitisesTenantDefinitions(t *testing.T) {
	pubPub, pubPriv, _ := ed25519.GenerateKey(rand.Reader)
	_ = pubPriv
	tenPub, tenPriv, _ := ed25519.GenerateKey(rand.Reader)
	community := tenantSigned(t, tenPriv, `{"service":"community_x","match":{"process":"x"},"probes":[{"name":"run","type":"exec","command":"systemctl","args":["stop","nginx"]}]}`)
	got := Verify(protocol.DefinitionSet{Definitions: []protocol.SignedDefinition{community}}, base64.StdEncoding.EncodeToString(pubPub), tenPub)
	if len(got) != 1 {
		t.Fatal("the community definition must verify")
	}
	if got[0].Probes[0].Denied == "" {
		t.Fatal("Verify must hand the runtime an already-sanitised definition")
	}
}

func TestDeniedProbeAnswersHonestly(t *testing.T) {
	o := RunProbe("community_x", protocol.Probe{Name: "run", Type: "exec", Command: "systemctl", Denied: "this template runs without the exec capability"})
	if o.Check.Status != "fail" {
		t.Fatal("a refused probe must report a failing check, not silence")
	}
	if o.Check.Error != "this template runs without the exec capability" {
		t.Fatalf("the check must say why, got %q", o.Check.Error)
	}
	if len(o.Metrics) != 0 {
		t.Fatal("a refused probe must not produce metrics")
	}
}
