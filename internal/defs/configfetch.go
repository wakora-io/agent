package defs

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"wakora.io/agent/internal/atomicfile"
)

const configFetchCap = 512 * 1024

const configSecretWords = `(?:password|passwd|secret|passphrase|community|private-key|wpa2?-pre-shared-key|pre-shared-key|auth-key|privacy-key)`

var defaultConfigMasks = []string{
	`((?i)` + configSecretWords + `["']?[ \t]*[=:][ \t]*)(?:"[^"\n]*"|'[^'\n]*'|[^\s"']+)`,
	`((?i)` + configSecretWords + `[ \t]+)(?:"[^"\n]*"|'[^'\n]*'|[^\n]+)`,
}

func NormalizeConfig(raw string, drops []string) string {
	res := make([]*regexp.Regexp, 0, len(drops))
	for _, d := range drops {
		re, err := regexp.Compile(d)
		if err != nil {
			continue
		}
		res = append(res, re)
	}
	if len(res) == 0 {
		return raw
	}
	lines := strings.Split(raw, "\n")
	out := lines[:0]
	for _, ln := range lines {
		dropped := false
		for _, re := range res {
			if re.MatchString(ln) {
				dropped = true
				break
			}
		}
		if !dropped {
			out = append(out, ln)
		}
	}
	return strings.Join(out, "\n")
}

func MaskConfig(raw string, extra []string) (string, error) {
	res := make([]*regexp.Regexp, 0, len(defaultConfigMasks)+len(extra))
	for _, p := range append(append([]string{}, defaultConfigMasks...), extra...) {
		re, err := regexp.Compile(p)
		if err != nil {
			return "", fmt.Errorf("mask %q in the definition does not compile, nothing was stored: %v", p, err)
		}
		res = append(res, re)
	}
	for _, re := range res {
		if re.NumSubexp() > 0 {
			raw = re.ReplaceAllString(raw, "${1}***")
		} else {
			raw = re.ReplaceAllString(raw, "***")
		}
	}
	return raw, nil
}

type capBuffer struct {
	mu   sync.Mutex
	buf  []byte
	over bool
}

func (c *capBuffer) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	room := configFetchCap - len(c.buf)
	if len(p) > room {
		c.buf = append(c.buf, p[:max(room, 0)]...)
		c.over = true
	} else {
		c.buf = append(c.buf, p...)
	}
	return len(p), nil
}

func ConfigSha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func hostKeyFingerprint(key ssh.PublicKey) string {
	h := sha256.Sum256(key.Marshal())
	return base64.StdEncoding.EncodeToString(h[:])
}

func pinnedHostKey(knownPath, addr string) (string, error) {
	b, err := os.ReadFile(knownPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	for _, ln := range strings.Split(string(b), "\n") {
		f := strings.Fields(ln)
		if len(f) == 2 && f[0] == addr {
			return f[1], nil
		}
	}
	return "", nil
}

func pinHostKey(knownPath, addr, fp string) error {
	b, _ := os.ReadFile(knownPath)
	body := strings.TrimSpace(string(b))
	if body != "" {
		body += "\n"
	}
	body += addr + " " + fp + "\n"
	return atomicfile.Write(knownPath, []byte(body), 0o600)
}

func trustOnFirstUse(knownPath string) ssh.HostKeyCallback {
	return func(hostport string, remote net.Addr, key ssh.PublicKey) error {
		fp := hostKeyFingerprint(key)
		pinned, err := pinnedHostKey(knownPath, hostport)
		if err != nil {
			return err
		}
		if pinned == "" {
			return pinHostKey(knownPath, hostport, fp)
		}
		if pinned != fp {
			return fmt.Errorf("ssh host key of %s changed (pinned %s, offered %s) - remove the pin from %s only after verifying the device", hostport, pinned[:12], fp[:12], knownPath)
		}
		return nil
	}
}

func FetchDeviceConfig(host string, port int, user, pass, command string, timeout time.Duration, knownPath string) (string, error) {
	if command == "" {
		return "", errors.New("no fetch command in the definition")
	}
	if port <= 0 {
		port = 22
	}
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass), ssh.KeyboardInteractive(func(string, string, []string, []bool) ([]string, error) { return []string{pass}, nil })},
		HostKeyCallback: trustOnFirstUse(knownPath),
		Timeout:         timeout,
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return "", err
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()

	out := &capBuffer{}
	sess.Stdout = out
	sess.Stderr = out
	done := make(chan error, 1)
	go func() { done <- sess.Run(command) }()
	select {
	case rerr := <-done:
		if rerr != nil {
			return "", fmt.Errorf("the fetch command failed, nothing was stored: %v", rerr)
		}
		out.mu.Lock()
		defer out.mu.Unlock()
		if out.over {
			return "", fmt.Errorf("the configuration is larger than %d KiB, nothing was stored", configFetchCap/1024)
		}
		return string(out.buf), nil
	case <-time.After(timeout + 5*time.Second):
		return "", fmt.Errorf("the fetch command did not finish within %s", timeout+5*time.Second)
	}
}
