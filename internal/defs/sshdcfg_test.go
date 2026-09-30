package defs

import (
	"os"
	"path/filepath"
	"testing"

	"wakora.io/agent/internal/protocol"
)

var sshdDoorRules = []protocol.ParseRule{
	{Name: "svc.ssh.root_login_permitted", Regex: `(?im)^permitrootlogin\s+yes`, Count: true},
	{Name: "svc.ssh.password_auth_on", Regex: `(?im)^passwordauthentication\s+yes`, Count: true},
}

var sshdFactRules = []protocol.ParseRule{
	{Name: "permitRootLogin", Regex: `(?im)^permitrootlogin\s+(\S+)`},
	{Name: "passwordAuth", Regex: `(?im)^passwordauthentication\s+(\S+)`},
	{Name: "port", Regex: `(?im)^port (\d+)`},
}

func sshdFallbackOutcome(t *testing.T, path string) Outcome {
	t.Helper()
	cfg, ok := sshdConfigEffective(path)
	if !ok {
		t.Fatal("config not read")
	}
	var o Outcome
	applyMetricRules(&o, sshdDoorRules, cfg)
	applyFactRules(&o, sshdFactRules, cfg)
	return o
}

func sshdMetric(o Outcome, name string) float64 {
	for _, m := range o.Metrics {
		if m.Name == name {
			return m.Value
		}
	}
	return -1
}

func sshdWriteFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSshdFallbackFollowsIncludesAndStopsAtMatch(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "sshd_config")
	sshdWriteFile(t, main, "Include sshd_config.d/*.conf\n#PasswordAuthentication yes\nPermitRootLogin yes\nPort = 2222\nMatch User deploy\n    PasswordAuthentication yes\n")
	sshdWriteFile(t, filepath.Join(dir, "sshd_config.d", "50-cloud-init.conf"), "PasswordAuthentication no\n")
	sshdWriteFile(t, filepath.Join(dir, "sshd_config.d", "60-local.conf"), "PasswordAuthentication yes\n")

	o := sshdFallbackOutcome(t, main)
	if v := sshdMetric(o, "svc.ssh.password_auth_on"); v != 0 {
		t.Fatalf("an include earlier in the stream wins and a Match block is not global, password_auth_on=%v", v)
	}
	if v := sshdMetric(o, "svc.ssh.root_login_permitted"); v != 1 {
		t.Fatalf("root_login_permitted=%v", v)
	}
	if o.Facts["passwordAuth"] != "no" || o.Facts["permitRootLogin"] != "yes" || o.Facts["port"] != "2222" {
		t.Fatalf("facts %+v", o.Facts)
	}
}

func TestSshdFallbackFillsSshdDefaults(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "sshd_config")
	sshdWriteFile(t, main, "# stock file\nUsePAM yes\n")

	o := sshdFallbackOutcome(t, main)
	if v := sshdMetric(o, "svc.ssh.password_auth_on"); v != 1 {
		t.Fatalf("passwords are on by default, password_auth_on=%v", v)
	}
	if v := sshdMetric(o, "svc.ssh.root_login_permitted"); v != 0 {
		t.Fatalf("root login defaults to prohibit-password, root_login_permitted=%v", v)
	}
	if o.Facts["port"] != "22" || o.Facts["permitRootLogin"] != "prohibit-password" {
		t.Fatalf("facts %+v", o.Facts)
	}
}

func TestSshdPrivsepErrorIsRecognized(t *testing.T) {
	if !sshdPrivsepMissing([]byte("Missing privilege separation directory: /run/sshd\n")) {
		t.Fatal("the privsep message was not recognized")
	}
	if sshdPrivsepMissing([]byte("/etc/ssh/sshd_config line 3: Bad configuration option: Foo")) {
		t.Fatal("a real config error must stay a failure")
	}
	if _, ok := sshdConfigEffective(filepath.Join(t.TempDir(), "missing")); ok {
		t.Fatal("a missing config file must not produce values")
	}
}
