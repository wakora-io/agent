//go:build linux

package defs

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"wakora.io/agent/internal/protocol"
)

type cisFinding struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

func runCIS(o *Outcome, service string) {
	o.Check.Kind = "cis"
	o.Check.Status = "ok"
	pass, fail := 0, 0
	var findings []cisFinding
	record := func(ok bool, id, title, sev, detail string) {
		if ok {
			pass++
			return
		}
		fail++
		findings = append(findings, cisFinding{ID: id, Title: title, Severity: sev, Detail: detail})
	}

	if mode, ok := cisFileMode("/etc/passwd"); ok {
		record(mode&0o022 == 0, "passwd-perm", "/etc/passwd is world/group-writable", "high", cisModeStr(mode))
	}
	if mode, ok := cisFileMode("/etc/shadow"); ok {
		record(mode&0o037 == 0, "shadow-perm", "/etc/shadow is group-writable or world-accessible", "critical", cisModeStr(mode))
	}
	if mode, ok := cisFileMode("/etc/group"); ok {
		record(mode&0o022 == 0, "group-perm", "/etc/group is world/group-writable", "high", cisModeStr(mode))
	}
	if mode, ok := cisFileMode("/etc/gshadow"); ok {
		record(mode&0o037 == 0, "gshadow-perm", "/etc/gshadow is group-writable or world-accessible", "high", cisModeStr(mode))
	}
	if mode, ok := cisFileMode("/etc/ssh/sshd_config"); ok {
		record(mode&0o077 == 0, "sshd-config-perm", "sshd_config readable beyond root", "medium", cisModeStr(mode))
	}

	if sshd, ok := cisSshdEffective(); ok {
		door := func(key, id, title, sev, detail string) {
			v, has := sshd[key]
			if !has {
				return
			}
			record(v != "yes", id, title, sev, detail)
		}
		door("permitrootlogin", "sshd-root-login", "sshd permits root login", "high", "PermitRootLogin should be no or prohibit-password")
		door("passwordauthentication", "sshd-password-auth", "sshd accepts password auth", "medium", "prefer key-based auth")
		door("permitemptypasswords", "sshd-empty-pass", "sshd permits empty passwords", "critical", "PermitEmptyPasswords should be no")
		door("x11forwarding", "sshd-x11", "sshd X11 forwarding enabled", "low", "disable unless needed")
	}

	record(cisSysctl("net/ipv4/tcp_syncookies") == "1", "tcp-syncookies", "TCP SYN cookies disabled", "medium", "net.ipv4.tcp_syncookies should be 1")
	record(cisSysctl("fs/suid_dumpable") == "0", "suid-dumpable", "SUID core dumps allowed", "medium", "fs.suid_dumpable should be 0")
	record(cisSysctl("kernel/randomize_va_space") == "2", "aslr", "ASLR not fully enabled", "medium", "kernel.randomize_va_space should be 2")
	record(cisSysctl("net/ipv4/conf/all/accept_redirects") == "0", "icmp-redirects", "ICMP redirects accepted", "low", "net.ipv4.conf.all.accept_redirects should be 0")

	record(cisAuditd(), "auditd", "auditd is not installed", "medium", "the audit daemon records security-relevant events")
	record(cisFirewall(), "firewall", "no host firewall detected", "medium", "ufw, firewalld or nftables should be active")

	if defs, ok := cisReadFile("/etc/login.defs"); ok {
		if ok, has := cisLoginDefsMax(defs, "PASS_MAX_DAYS", 365); has {
			record(ok, "pass-max-days", "password max-age too long", "low", "PASS_MAX_DAYS should be <= 365")
		}
		if ok, has := cisLoginDefsUmask(defs); has {
			record(ok, "umask", "default umask weaker than 027", "low", "UMASK should be 027 or stricter")
		}
	}

	total := pass + fail
	score := 100
	if total > 0 {
		score = pass * 100 / total
	}
	o.Metrics = append(o.Metrics,
		protocol.MetricPoint{Name: "svc." + service + ".score", Value: float64(score)},
		protocol.MetricPoint{Name: "svc." + service + ".pass", Value: float64(pass)},
		protocol.MetricPoint{Name: "svc." + service + ".fail", Value: float64(fail)},
	)
	detail, _ := json.Marshal(map[string]any{"score": score, "pass": pass, "fail": fail, "findings": findings})
	o.Events = append(o.Events, protocol.AgentEvent{Kind: "cis_scan", Detail: string(detail), Timestamp: time.Now().Unix()})
}

func cisFileMode(path string) (os.FileMode, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, false
	}
	return fi.Mode().Perm(), true
}

func cisModeStr(m os.FileMode) string {
	return "mode " + strconv.FormatUint(uint64(m), 8)
}

func cisReadFile(path string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	if len(data) > 1<<20 {
		data = data[:1<<20]
	}
	return string(data), true
}

var cisWSRe = regexp.MustCompile(`\s+`)

func cisSshdEffective() (map[string]string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "sshd", "-T").Output(); err == nil && len(out) > 0 {
		return cisSshdParse(string(out), false), true
	}
	if cfg, ok := cisReadFile("/etc/ssh/sshd_config"); ok {
		return cisSshdParse(cfg, true), true
	}
	return nil, false
}

func cisSshdParse(s string, stopAtMatch bool) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := cisWSRe.Split(line, 2)
		if len(fields) != 2 {
			continue
		}
		key := strings.ToLower(fields[0])
		if stopAtMatch && key == "match" {
			break
		}
		if _, seen := m[key]; seen {
			continue
		}
		m[key] = strings.ToLower(strings.TrimSpace(fields[1]))
	}
	return m
}

func cisSysctl(path string) string {
	data, err := os.ReadFile("/proc/sys/" + path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func cisAuditd() bool {
	for _, p := range []string{"/sbin/auditd", "/usr/sbin/auditd"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

func cisFirewall() bool {
	if data, err := os.ReadFile("/proc/net/ip_tables_names"); err == nil && len(strings.TrimSpace(string(data))) > 0 {
		return true
	}
	if data, err := os.ReadFile("/proc/net/nf_tables"); err == nil && len(strings.TrimSpace(string(data))) > 0 {
		return true
	}
	for _, p := range []string{"/sys/module/nf_tables", "/sys/module/iptable_filter", "/sys/module/ip_tables"} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

func cisLoginDefsMax(defs, key string, max int) (bool, bool) {
	for _, line := range strings.Split(defs, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := cisWSRe.Split(line, 2)
		if len(fields) != 2 || fields[0] != key {
			continue
		}
		if n, err := strconv.Atoi(strings.TrimSpace(fields[1])); err == nil {
			return n <= max, true
		}
	}
	return false, false
}

func cisLoginDefsUmask(defs string) (bool, bool) {
	for _, line := range strings.Split(defs, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := cisWSRe.Split(line, 2)
		if len(fields) != 2 || fields[0] != "UMASK" {
			continue
		}
		v := strings.TrimSpace(fields[1])
		if n, err := strconv.ParseInt(v, 8, 32); err == nil {
			return n&0o027 == 0o027, true
		}
	}
	return false, false
}
