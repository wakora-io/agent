package defs

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"wakora.io/agent/internal/discovery"
	"wakora.io/agent/internal/protocol"
)

func signDef(t *testing.T, priv ed25519.PrivateKey, def string) protocol.SignedDefinition {
	t.Helper()
	var parsed any
	if err := json.Unmarshal([]byte(def), &parsed); err != nil {
		t.Fatal(err)
	}
	canonical, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.SignedDefinition{
		Def: canonical,
		Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canonical)),
	}
}

func TestVerifyUninstallOrder(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	order := func(uuid string, issued int64) string {
		payload, _ := json.Marshal(struct {
			UUID     string `json:"uuid"`
			IssuedAt int64  `json:"issuedAt"`
		}{uuid, issued})
		return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload))
	}
	now := time.Now().Unix()
	env := order("abc-123", now)
	if !VerifyUninstallOrder(env, pubB64, "abc-123", t.TempDir()) {
		t.Fatal("a valid order for this host must verify")
	}
	if VerifyUninstallOrder(env, pubB64, "other-uuid", t.TempDir()) {
		t.Fatal("an order for a DIFFERENT uuid must be rejected (no cross-host wipe)")
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if VerifyUninstallOrder(env, base64.StdEncoding.EncodeToString(other), "abc-123", t.TempDir()) {
		t.Fatal("an order signed by a non-publisher key must be rejected")
	}
	if VerifyUninstallOrder("garbage.sig", pubB64, "abc-123", t.TempDir()) || VerifyUninstallOrder("", pubB64, "abc-123", t.TempDir()) {
		t.Fatal("malformed envelopes must be rejected")
	}
	tampered := order("abc-123", now)
	if VerifyUninstallOrder(tampered[:2]+"xx"+tampered[4:], pubB64, "abc-123", t.TempDir()) {
		t.Fatal("a tampered payload must be rejected")
	}
	if VerifyUninstallOrder(order("abc-123", 1786000000), pubB64, "abc-123", t.TempDir()) {
		t.Fatal("a stale order must be rejected - a captured envelope is not a licence to wipe the host later")
	}
	if VerifyUninstallOrder(order("abc-123", 0), pubB64, "abc-123", t.TempDir()) {
		t.Fatal("an order without an issue time must be rejected")
	}
}

func TestVerifyUninstallOrderRefusesAReplayOfTheSameOrder(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	payload, _ := json.Marshal(struct {
		UUID     string `json:"uuid"`
		IssuedAt int64  `json:"issuedAt"`
	}{"abc-123", time.Now().Unix()})
	env := base64.RawURLEncoding.EncodeToString(payload) + "." + base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload))
	state := t.TempDir()
	if !VerifyUninstallOrder(env, pubB64, "abc-123", state) {
		t.Fatal("the first order must verify")
	}
	if VerifyUninstallOrder(env, pubB64, "abc-123", state) {
		t.Fatal("the same order must not verify twice")
	}
}

func TestVerifyAcceptsValidRejectsTampered(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	good := signDef(t, priv, `{"service":"nginx","match":{"process":"nginx"},"probes":[]}`)
	verified := Verify(protocol.DefinitionSet{Definitions: []protocol.SignedDefinition{good}}, pubB64, nil)
	if len(verified) != 1 || verified[0].Service != "nginx" {
		t.Fatalf("valid definition rejected: %v", verified)
	}

	tampered := good
	raw := append([]byte{}, good.Def...)
	raw[len(raw)-2] ^= 1
	tampered.Def = raw
	verified = Verify(protocol.DefinitionSet{Definitions: []protocol.SignedDefinition{tampered}}, pubB64, nil)
	if len(verified) != 0 {
		t.Fatal("tampered definition accepted")
	}

	verified = Verify(protocol.DefinitionSet{Definitions: []protocol.SignedDefinition{good}}, "not-a-key", nil)
	if len(verified) != 0 {
		t.Fatal("definitions accepted without valid publisher key")
	}
}

func TestMatchesProcessPrefix(t *testing.T) {
	facts := []discovery.Fact{
		{Kind: "process", Key: "php-fpm8.2", Payload: `{"cmdline":"php-fpm: master process (/etc/php/8.2/fpm/php-fpm.conf)"}`},
	}
	d := protocol.Definition{Service: "php-fpm", Match: protocol.Match{ProcessPrefix: "php-fpm"}}
	if !Matches(d, facts) {
		t.Fatal("prefix must match versioned process name")
	}
	d.Match.ProcessPrefix = "nginx"
	if Matches(d, facts) {
		t.Fatal("wrong prefix matched")
	}
}

func TestMatchesInit(t *testing.T) {
	systemd := []discovery.Fact{
		{Kind: "process", Key: "sshd"},
		{Kind: "init", Key: "systemd"},
	}
	openrc := []discovery.Fact{
		{Kind: "process", Key: "sshd"},
		{Kind: "init", Key: "openrc"},
	}
	windows := []discovery.Fact{
		{Kind: "process", Key: "svchost.exe"},
	}

	d := protocol.Definition{Service: "ssh", Match: protocol.Match{Process: "sshd", Init: "systemd"}}
	if !Matches(d, systemd) {
		t.Fatal("systemd variant must match systemd host")
	}
	if Matches(d, openrc) {
		t.Fatal("systemd variant matched openrc host")
	}

	fim := protocol.Definition{Service: "security", Match: protocol.Match{Init: "*"}}
	if !Matches(fim, systemd) || !Matches(fim, openrc) {
		t.Fatal("init wildcard must match any linux host")
	}
	if Matches(fim, windows) {
		t.Fatal("init wildcard matched host without init fact")
	}
}

func TestMatchesProcessExeFallback(t *testing.T) {
	pm2Host := []discovery.Fact{
		{Kind: "process", Key: "node /opt/app/index.js", Payload: `{"cmdline":"node /opt/app/index.js","exe":"/usr/bin/node"}`},
		{Kind: "process", Key: "PM2 v7.0.3: God", Payload: `{"exe":"/usr/bin/node"}`},
	}
	nextHost := []discovery.Fact{
		{Kind: "process", Key: "next-server (v14)", Payload: `{"exe":"/usr/local/bin/node"}`},
	}
	exporterHost := []discovery.Fact{
		{Kind: "process", Key: "node_exporter", Payload: `{"exe":"/usr/bin/node_exporter"}`},
	}
	d := protocol.Definition{Service: "node", Match: protocol.Match{Process: "node"}}
	if !Matches(d, pm2Host) {
		t.Fatal("pm2-retitled node must match via exe basename")
	}
	if !Matches(d, nextHost) {
		t.Fatal("next-server must match via exe basename")
	}
	if Matches(d, exporterHost) {
		t.Fatal("node_exporter must not match the node definition")
	}
}

func TestProcFacts(t *testing.T) {
	facts := []discovery.Fact{
		{Kind: "process", Key: "sshd", Payload: `{"cmdline":"sshd: /usr/sbin/sshd"}`},
		{Kind: "process", Key: "php-fpm8.2", Payload: `{"cmdline":"php-fpm: master process (/etc/php/8.2/fpm/php-fpm.conf)","exe":"/usr/sbin/php-fpm8.2"}`},
	}
	p := protocol.Probe{Type: "procfact", Process: "php-fpm", Facts: []protocol.ParseRule{
		{Name: "confFile", Regex: `master process \(([^)]+)\)`},
		{Name: "version", Regex: `/etc/php/([0-9.]+)/`},
	}}
	out := ProcFacts(facts, p)
	if out["confFile"] != "/etc/php/8.2/fpm/php-fpm.conf" || out["version"] != "8.2" {
		t.Fatalf("procfacts wrong: %v", out)
	}
	if ProcFacts(facts, protocol.Probe{Process: "mongod", Facts: p.Facts}) != nil {
		t.Fatal("absent process must yield nil")
	}
}

func TestMatches(t *testing.T) {
	facts := []discovery.Fact{
		{Kind: "process", Key: "nginx"},
		{Kind: "port", Key: "80/tcp"},
		{Kind: "package", Key: "nginx"},
	}
	cases := []struct {
		match protocol.Match
		want  bool
	}{
		{protocol.Match{Process: "nginx"}, true},
		{protocol.Match{Process: "nginx", Port: "80/tcp"}, true},
		{protocol.Match{Process: "nginx", Port: "443/tcp"}, false},
		{protocol.Match{Process: "apache2"}, false},
		{protocol.Match{Package: "nginx", Process: "nginx", Port: "80/tcp"}, true},
		{protocol.Match{}, false},
	}
	for i, c := range cases {
		got := Matches(protocol.Definition{Service: "s", Match: c.match}, facts)
		if got != c.want {
			t.Fatalf("case %d: got %v want %v", i, got, c.want)
		}
	}
}

func TestExtract(t *testing.T) {
	out := []byte("nginx version: nginx/1.22.1\nbuilt with OpenSSL")
	v, ok := extract(out, `nginx/([0-9][0-9a-zA-Z.]*)`)
	if !ok || v != "1.22.1" {
		t.Fatalf("extract: %q %v", v, ok)
	}
	if _, ok := extract(out, `apache/([0-9.]+)`); ok {
		t.Fatal("extract matched nothing")
	}
	if _, ok := extract(out, `broken(regex`); ok {
		t.Fatal("broken regex must not match")
	}
}

func TestExecAllowlistBlocksUnknown(t *testing.T) {
	o := RunProbe("svc", protocol.Probe{Name: "x", Type: "exec", Command: "rm", Args: []string{"-rf", "/"}})
	if o.Check.Status != "fail" || o.Check.Error != "command not in allow-list" {
		t.Fatalf("allow-list bypass: %+v", o.Check)
	}
	o = RunProbe("svc", protocol.Probe{Name: "x", Type: "exec", Command: "/usr/bin/nginx"})
	if o.Check.Status != "fail" {
		t.Fatal("path traversal accepted")
	}
}

func TestApplyKVMetricsRatiosFacts(t *testing.T) {
	p := protocol.Probe{
		KVMetrics: []protocol.KVMetric{{Name: "svc.mysql.uptime", Key: "Uptime"}},
		KVRatios: []protocol.KVRatio{
			{Name: "svc.mysql.qps", Num: "Questions", Den: "Uptime"},
			{Name: "svc.x.zeroden", Num: "Questions", Den: "Zero"},
		},
		KVFacts: []protocol.KVMetric{{Name: "slowLog", Key: "slow_query_log_file"}, {Name: "missing", Key: "nope"}},
	}
	o := Outcome{}
	applyKV(&o, p, map[string]string{"Uptime": "200", "Questions": "1000", "Zero": "0", "slow_query_log_file": " /var/log/mysql/slow.log "})
	got := map[string]float64{}
	for _, m := range o.Metrics {
		got[m.Name] = m.Value
	}
	if got["svc.mysql.uptime"] != 200 {
		t.Fatalf("kv metric lost: %+v", o.Metrics)
	}
	if got["svc.mysql.qps"] != 5 {
		t.Fatalf("ratio wrong: %+v", o.Metrics)
	}
	if _, ok := got["svc.x.zeroden"]; ok {
		t.Fatal("a zero denominator must not emit")
	}
	if o.Facts["slowLog"] != "/var/log/mysql/slow.log" {
		t.Fatalf("kv fact wrong: %+v", o.Facts)
	}
	if _, ok := o.Facts["missing"]; ok {
		t.Fatal("an absent key must not mint a fact")
	}
}

func TestTCPProbeUnresolvedPortFailsHonestly(t *testing.T) {
	o := RunProbe("ssh", protocol.Probe{Name: "port", Type: "tcp", PortProcess: "sshd"})
	if o.Check.Status != "fail" {
		t.Fatalf("empty address must fail, got %q", o.Check.Status)
	}
	if !strings.Contains(o.Check.Error, "sshd") || strings.Contains(o.Check.Error, "missing address") {
		t.Fatalf("want the socket-activation message, got %q", o.Check.Error)
	}
	o = RunProbe("svc", protocol.Probe{Name: "x", Type: "tcp"})
	if o.Check.Status != "fail" || o.Check.Error != "no address to dial" {
		t.Fatalf("bare empty address: %+v", o.Check)
	}
}
