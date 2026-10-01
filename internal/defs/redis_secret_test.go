package defs

import (
	"bytes"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"wakora.io/agent/internal/protocol"
	"wakora.io/agent/internal/secret"
)

type noauthRedis struct {
	ln   net.Listener
	mu   sync.Mutex
	seen bytes.Buffer
}

func startNoauthRedis(t *testing.T) *noauthRedis {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &noauthRedis{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *noauthRedis) serve(c net.Conn) {
	defer c.Close()
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			s.mu.Lock()
			s.seen.Write(buf[:n])
			s.mu.Unlock()
			cmds := 0
			for i, line := range strings.Split(string(buf[:n]), "\r\n") {
				if strings.HasPrefix(line, "*") && (i == 0 || line != "") {
					cmds++
				}
			}
			if cmds == 0 {
				cmds = 1
			}
			for i := 0; i < cmds; i++ {
				c.Write([]byte("-NOAUTH Authentication required.\r\n"))
			}
		}
		if err != nil {
			return
		}
	}
}

func (s *noauthRedis) saw(sub string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Contains(s.seen.String(), sub)
}

func TestRedisSecretOptionalUnsetHints(t *testing.T) {
	srv := startNoauthRedis(t)
	var o Outcome
	p := protocol.Probe{Name: "info", Type: "redis", Address: srv.ln.Addr().String(), SecretOpt: "redis-monitor"}
	runRedis(&o, "redis", p, 2*time.Second, func(string) (secret.Cred, bool) { return secret.Cred{}, false })
	if o.Check.Status != "fail" {
		t.Fatalf("want fail, got %s", o.Check.Status)
	}
	if !strings.Contains(o.Check.Error, "wakora secret set redis-monitor") {
		t.Fatalf("hint missing: %s", o.Check.Error)
	}
}

func TestRedisSecretOptionalResolvedSendsPassword(t *testing.T) {
	srv := startNoauthRedis(t)
	var o Outcome
	p := protocol.Probe{Name: "info", Type: "redis", Address: srv.ln.Addr().String(), SecretOpt: "redis-monitor"}
	runRedis(&o, "redis", p, 2*time.Second, func(name string) (secret.Cred, bool) {
		if name != "redis-monitor" {
			t.Fatalf("wrong secret name %s", name)
		}
		return secret.Cred{Pass: "pw-for-test"}, true
	})
	if !srv.saw("pw-for-test") {
		t.Fatal("password was not sent")
	}
	if strings.Contains(o.Check.Error, "wakora secret set") {
		t.Fatalf("hint must not appear when a secret is set: %s", o.Check.Error)
	}
}

func TestRedisAuthRequired(t *testing.T) {
	cases := map[string]bool{
		"NOAUTH Authentication required.":                               true,
		"WRONGPASS invalid username-password pair or user is disabled.": true,
		"dial tcp 127.0.0.1:6379: connect: connection refused":          false,
	}
	for msg, want := range cases {
		if got := redisAuthRequired(errString(msg)); got != want {
			t.Fatalf("%q: got %v", msg, got)
		}
	}
}

type errString string

func (e errString) Error() string { return string(e) }
