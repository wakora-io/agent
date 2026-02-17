//go:build linux

package discovery

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

func Collect() []Fact {
	var facts []Fact
	facts = append(facts, processes()...)
	facts = append(facts, ports()...)
	facts = append(facts, packages()...)
	facts = append(facts, units()...)
	facts = append(facts, netFacts()...)
	facts = append(facts, initFact())
	return facts
}

func initFact() Fact {
	system := "unknown"
	switch {
	case statOK("/run/systemd/system"):
		system = "systemd"
	case statOK("/run/openrc"):
		system = "openrc"
	case statOK("/etc/inittab"):
		system = "sysvinit"
	}
	return Fact{Kind: "init", Key: system, Payload: "{}"}
}

func statOK(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func ChangeSignal() string {
	h := sha256.New()
	if fi, err := os.Stat("/var/lib/dpkg/status"); err == nil {
		fmt.Fprintf(h, "dpkg:%d:%d;", fi.ModTime().UnixNano(), fi.Size())
	}
	if fi, err := os.Stat("/var/lib/rpm"); err == nil {
		fmt.Fprintf(h, "rpm:%d;", fi.ModTime().UnixNano())
	}
	if fi, err := os.Stat("/lib/apk/db/installed"); err == nil {
		fmt.Fprintf(h, "apk:%d:%d;", fi.ModTime().UnixNano(), fi.Size())
	}
	for _, k := range listenKeys() {
		io.WriteString(h, k+";")
	}
	return hex.EncodeToString(h.Sum(nil))
}

func listenKeys() []string {
	seen := map[string]bool{}
	for _, src := range portSources {
		data, err := os.ReadFile(src.path)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		for _, line := range lines[1:] {
			f := strings.Fields(line)
			if len(f) < 4 || f[3] != src.state {
				continue
			}
			local := f[1]
			colon := strings.LastIndexByte(local, ':')
			if colon < 0 {
				continue
			}
			port, err := strconv.ParseUint(local[colon+1:], 16, 16)
			if err != nil || port == 0 {
				continue
			}
			seen[strconv.FormatUint(port, 10)+"/"+src.proto] = true
		}
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func processes() []Fact {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	agg := map[string]*procInfo{}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if cg, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cgroup")); err == nil && containerCgroup(string(cg)) {
			continue
		}
		comm, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(comm))
		if name == "" {
			continue
		}
		if p := agg[name]; p != nil {
			p.Count++
			continue
		}
		cmdRaw, _ := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		cmd := strings.TrimSpace(strings.ReplaceAll(string(cmdRaw), "\x00", " "))
		if len(cmd) > 300 {
			cmd = cmd[:300]
		}
		exe, _ := os.Readlink(filepath.Join("/proc", e.Name(), "exe"))
		agg[name] = &procInfo{Count: 1, Pid: pid, Cmdline: cmd, Exe: exe}
	}
	return sortedFacts("process", agg)
}

type portInfo struct {
	Addr    string `json:"addr,omitempty"`
	Pid     int    `json:"pid,omitempty"`
	Process string `json:"process,omitempty"`
}

var portSources = []struct {
	path  string
	proto string
	state string
}{
	{"/proc/net/tcp", "tcp", "0A"},
	{"/proc/net/tcp6", "tcp", "0A"},
	{"/proc/net/udp", "udp", "07"},
	{"/proc/net/udp6", "udp", "07"},
}

func ports() []Fact {
	inodePid := socketInodes()
	agg := map[string]*portInfo{}
	for _, src := range portSources {
		data, err := os.ReadFile(src.path)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		for _, line := range lines[1:] {
			f := strings.Fields(line)
			if len(f) < 10 || f[3] != src.state {
				continue
			}
			local := f[1]
			colon := strings.LastIndexByte(local, ':')
			if colon < 0 {
				continue
			}
			port, err := strconv.ParseUint(local[colon+1:], 16, 16)
			if err != nil || port == 0 {
				continue
			}
			key := strconv.FormatUint(port, 10) + "/" + src.proto
			if agg[key] != nil {
				continue
			}
			info := &portInfo{Addr: decodeAddr(local[:colon])}
			if inode := f[9]; inode != "0" {
				if pid, ok := inodePid[inode]; ok {
					info.Pid = pid
					if comm, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm")); err == nil {
						info.Process = strings.TrimSpace(string(comm))
					}
				}
			}
			agg[key] = info
		}
	}
	return sortedFacts("port", agg)
}

func decodeAddr(hexAddr string) string {
	if len(hexAddr) == 8 {
		b, err := strconv.ParseUint(hexAddr, 16, 32)
		if err != nil {
			return ""
		}
		return strconv.FormatUint(b&0xff, 10) + "." +
			strconv.FormatUint(b>>8&0xff, 10) + "." +
			strconv.FormatUint(b>>16&0xff, 10) + "." +
			strconv.FormatUint(b>>24&0xff, 10)
	}
	if strings.Trim(hexAddr, "0") == "" {
		return "::"
	}
	return "ipv6"
}

func socketInodes() map[string]int {
	out := map[string]int{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fds, err := os.ReadDir(filepath.Join("/proc", e.Name(), "fd"))
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join("/proc", e.Name(), "fd", fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			if _, seen := out[inode]; !seen {
				out[inode] = pid
			}
		}
	}
	return out
}

func packages() []Fact {
	if facts := dpkgPackages(); facts != nil {
		return facts
	}
	if facts := rpmPackages(); facts != nil {
		return facts
	}
	return apkPackages()
}

func dpkgPackages() []Fact {
	f, err := os.Open("/var/lib/dpkg/status")
	if err != nil {
		return nil
	}
	defer f.Close()
	agg := map[string]*packageInfo{}
	var name, version string
	installed := false
	commit := func() {
		if name != "" && installed {
			agg[name] = &packageInfo{Version: version}
		}
		name, version, installed = "", "", false
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			commit()
		case strings.HasPrefix(line, "Package: "):
			name = line[9:]
		case strings.HasPrefix(line, "Version: "):
			version = line[9:]
		case strings.HasPrefix(line, "Status: "):
			installed = strings.HasSuffix(line, " installed")
		}
	}
	commit()
	return sortedFacts("package", agg)
}

func rpmPackages() []Fact {
	if _, err := os.Stat("/var/lib/rpm"); err != nil {
		return nil
	}
	out, err := exec.Command("rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\n").Output()
	if err != nil {
		return nil
	}
	agg := map[string]*packageInfo{}
	for _, line := range strings.Split(string(out), "\n") {
		name, version, ok := strings.Cut(line, "\t")
		if !ok || name == "" {
			continue
		}
		agg[name] = &packageInfo{Version: version}
	}
	return sortedFacts("package", agg)
}

func apkPackages() []Fact {
	data, err := os.ReadFile("/lib/apk/db/installed")
	if err != nil {
		return nil
	}
	return parseApkDB(string(data))
}

func parseApkDB(data string) []Fact {
	agg := map[string]*packageInfo{}
	var name, version string
	commit := func() {
		if name != "" {
			agg[name] = &packageInfo{Version: version}
		}
		name, version = "", ""
	}
	for _, line := range strings.Split(data, "\n") {
		switch {
		case line == "":
			commit()
		case strings.HasPrefix(line, "P:"):
			name = line[2:]
		case strings.HasPrefix(line, "V:"):
			version = line[2:]
		}
	}
	commit()
	return sortedFacts("package", agg)
}

type unitInfo struct {
	Load   string `json:"load,omitempty"`
	Active string `json:"active,omitempty"`
	Sub    string `json:"sub,omitempty"`
}

func units() []Fact {
	out, err := exec.Command("systemctl", "list-units", "--type=service", "--all", "--plain", "--no-legend", "--no-pager").Output()
	if err != nil {
		return nil
	}
	agg := map[string]*unitInfo{}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || !strings.HasSuffix(f[0], ".service") {
			continue
		}
		agg[f[0]] = &unitInfo{Load: f[1], Active: f[2], Sub: f[3]}
	}
	return sortedFacts("unit", agg)
}
