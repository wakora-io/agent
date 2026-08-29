package defs

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestNormalizeDropsVolatileLines(t *testing.T) {
	raw := "# aug/17/2026 01:02:03 by RouterOS 7.23.3\n/interface bridge\nadd name=br1\n"
	out := NormalizeConfig(raw, []string{`^# [a-z]{3}/\d`})
	if strings.Contains(out, "aug/17") {
		t.Fatalf("volatile line survived: %q", out)
	}
	if !strings.Contains(out, "add name=br1") {
		t.Fatalf("real line dropped: %q", out)
	}
	if NormalizeConfig(raw, []string{"[broken"}) != raw {
		t.Fatal("a broken regex must leave the config untouched")
	}
}

func TestMaskHidesSecretsByDefault(t *testing.T) {
	raw := "set snmp community=labsecret\nset user password=\"hunter2\"\nset wpa2-pre-shared-key=wifikey99\nset name=keepme\n"
	out := MaskConfig(raw, nil)
	for _, leak := range []string{"labsecret", "hunter2", "wifikey99"} {
		if strings.Contains(out, leak) {
			t.Fatalf("secret %q leaked: %q", leak, out)
		}
	}
	if !strings.Contains(out, "keepme") {
		t.Fatalf("non-secret value masked: %q", out)
	}
	extra := MaskConfig("token abc123", []string{`(token )\S+`})
	if strings.Contains(extra, "abc123") || !strings.Contains(extra, "token ***") {
		t.Fatalf("definition mask not applied: %q", extra)
	}
	if ConfigSha(out) == ConfigSha(out+"x") {
		t.Fatal("sha must move with content")
	}
}

func testSSHServer(t *testing.T, reply string) (addr string, stop func()) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == "admin" && string(pass) == "labpass" {
				return nil, nil
			}
			return nil, ssh.ErrNoAuth
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(nc net.Conn) {
				sc, chans, reqs, herr := ssh.NewServerConn(nc, cfg)
				if herr != nil {
					return
				}
				defer sc.Close()
				go ssh.DiscardRequests(reqs)
				for newCh := range chans {
					ch, chReqs, cerr := newCh.Accept()
					if cerr != nil {
						continue
					}
					go func(ch ssh.Channel, chReqs <-chan *ssh.Request) {
						defer ch.Close()
						for req := range chReqs {
							if req.Type == "exec" {
								req.Reply(true, nil)
								ch.Write([]byte(reply))
								ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
								return
							}
							req.Reply(false, nil)
						}
					}(ch, chReqs)
				}
			}(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func TestFetchDeviceConfigOverSSHWithTOFU(t *testing.T) {
	addr, stop := testSSHServer(t, "# by RouterOS\n/export line one\npassword=topsecret\n")
	defer stop()
	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	for _, ch := range portStr {
		port = port*10 + int(ch-'0')
	}
	known := filepath.Join(t.TempDir(), "ssh-hostkeys")

	raw, err := FetchDeviceConfig(host, port, "admin", "labpass", "/export", 5*time.Second, known)
	if err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	if !strings.Contains(raw, "/export line one") {
		t.Fatalf("unexpected output: %q", raw)
	}

	if _, err := FetchDeviceConfig(host, port, "admin", "labpass", "/export", 5*time.Second, known); err != nil {
		t.Fatalf("second fetch against the pinned key: %v", err)
	}

	if _, err := FetchDeviceConfig(host, port, "admin", "wrong", "/export", 5*time.Second, known); err == nil {
		t.Fatal("a wrong password must fail")
	}

	stop()
	addr2, stop2 := testSSHServer(t, "other")
	defer stop2()
	host2, portStr2, _ := net.SplitHostPort(addr2)
	port2 := 0
	for _, ch := range portStr2 {
		port2 = port2*10 + int(ch-'0')
	}
	if err := pinHostKey(known, net.JoinHostPort(host2, portStr2), "AAAAfakepinnedfingerprintAAAA"); err != nil {
		t.Fatal(err)
	}
	if _, err := FetchDeviceConfig(host2, port2, "admin", "labpass", "/export", 5*time.Second, known); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("a changed host key must refuse, got: %v", err)
	}
}
