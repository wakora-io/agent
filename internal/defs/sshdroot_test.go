package defs

import (
	"path/filepath"
	"testing"

	"wakora.io/agent/internal/protocol"
)

var sshdVerdictRule = []protocol.ParseRule{
	{Name: "svc.ssh.root_login_permitted", Regex: `(?im)^rootpasswordlogin\s+yes`, Count: true},
}

func sshdVerdict(out string) float64 {
	var o Outcome
	applyMetricRules(&o, sshdVerdictRule, sshdWithVerdict([]byte(out)))
	return sshdMetric(o, "svc.ssh.root_login_permitted")
}

func TestRootLoginCountsOnlyWhenAPasswordCanReachRoot(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want float64
	}{
		{"key-only root on a proxmox node", "permitrootlogin yes\npasswordauthentication no\nkbdinteractiveauthentication no\n", 0},
		{"keyboard-interactive still asks pam for the password", "permitrootlogin yes\npasswordauthentication no\nkbdinteractiveauthentication yes\n", 1},
		{"plain passwords", "permitrootlogin yes\npasswordauthentication yes\nkbdinteractiveauthentication no\n", 1},
		{"prohibit-password never counts", "permitrootlogin prohibit-password\npasswordauthentication yes\nkbdinteractiveauthentication yes\n", 0},
		{"without-password is the old spelling", "permitrootlogin without-password\npasswordauthentication yes\n", 0},
		{"openssh 7 decides keyboard-interactive by challengeresponse", "permitrootlogin yes\npasswordauthentication no\nkbdinteractiveauthentication yes\nchallengeresponseauthentication no\n", 0},
		{"openssh 7 with challengeresponse on", "permitrootlogin yes\npasswordauthentication no\nkbdinteractiveauthentication no\nchallengeresponseauthentication yes\n", 1},
		{"no trailing newline", "permitrootlogin yes\npasswordauthentication yes", 1},
	}
	for _, c := range cases {
		if got := sshdVerdict(c.out); got != c.want {
			t.Errorf("%s: root_login_permitted=%v, want %v", c.name, got, c.want)
		}
	}
}

func TestRootLoginVerdictFromTheConfigFileFallback(t *testing.T) {
	dir := t.TempDir()
	keys := filepath.Join(dir, "keys")
	sshdWriteFile(t, keys, "PermitRootLogin yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n")
	cfg, ok := sshdConfigEffective(keys)
	if !ok {
		t.Fatal("config not read")
	}
	var o Outcome
	applyMetricRules(&o, sshdVerdictRule, sshdWithVerdict(cfg))
	if v := sshdMetric(o, "svc.ssh.root_login_permitted"); v != 0 {
		t.Fatalf("key-only root read from sshd_config, root_login_permitted=%v", v)
	}

	pam := filepath.Join(dir, "pam")
	sshdWriteFile(t, pam, "PermitRootLogin yes\nPasswordAuthentication no\n")
	cfg, _ = sshdConfigEffective(pam)
	o = Outcome{}
	applyMetricRules(&o, sshdVerdictRule, sshdWithVerdict(cfg))
	if v := sshdMetric(o, "svc.ssh.root_login_permitted"); v != 1 {
		t.Fatalf("keyboard-interactive is on by default, root_login_permitted=%v", v)
	}

	legacy := filepath.Join(dir, "legacy")
	sshdWriteFile(t, legacy, "PermitRootLogin yes\nPasswordAuthentication no\nChallengeResponseAuthentication no\n")
	cfg, _ = sshdConfigEffective(legacy)
	o = Outcome{}
	applyMetricRules(&o, sshdVerdictRule, sshdWithVerdict(cfg))
	if v := sshdMetric(o, "svc.ssh.root_login_permitted"); v != 0 {
		t.Fatalf("an old config switches keyboard-interactive off through challengeresponse, root_login_permitted=%v", v)
	}
}
