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
	"time"

	"golang.org/x/crypto/ssh"

	"wakora.io/agent/internal/atomicfile"
)

const configFetchCap = 512 * 1024

var defaultConfigMasks = []string{
	`((?i)(?:password|passwd|secret|passphrase|community|private-key|wpa2?-pre-shared-key|pre-shared-key|auth-key|privacy-key)[=:"' ]+)[^\s"']+`,
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

func MaskConfig(raw string, extra []string) string {
	pats := append(append([]string{}, defaultConfigMasks...), extra...)
	for _, p := range pats {
		re, err := regexp.Compile(p)
		if err != nil {
			continue
		}
		if re.NumSubexp() > 0 {
			raw = re.ReplaceAllString(raw, "${1}***")
		} else {
			raw = re.ReplaceAllString(raw, "***")
		}
	}
	return raw
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

	type result struct {
		out []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, rerr := sess.CombinedOutput(command)
		done <- result{out, rerr}
	}()
	select {
	case r := <-done:
		if r.err != nil && len(r.out) == 0 {
			return "", r.err
		}
		out := r.out
		if len(out) > configFetchCap {
			out = out[:configFetchCap]
		}
		return string(out), nil
	case <-time.After(timeout + 5*time.Second):
		return "", fmt.Errorf("the fetch command did not finish within %s", timeout+5*time.Second)
	}
}
