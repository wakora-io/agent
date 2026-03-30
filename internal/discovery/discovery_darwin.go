//go:build darwin

package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

var brewCellars = []string{"/usr/local/Cellar", "/opt/homebrew/Cellar"}

func Collect() []Fact {
	var facts []Fact
	facts = append(facts, processes()...)
	facts = append(facts, ports()...)
	facts = append(facts, packages()...)
	facts = append(facts, units()...)
	facts = append(facts, netFacts()...)
	facts = append(facts, hostFact())
	facts = append(facts, Fact{Kind: "init", Key: "launchd", Payload: "{}"})
	return facts
}

func osDetails() map[string]string {
	out, err := exec.Command("sw_vers", "-productVersion").Output()
	if err != nil {
		return map[string]string{"platform": "macos"}
	}
	version := strings.TrimSpace(string(out))
	pretty := "macOS"
	if version != "" {
		pretty = "macOS " + version
	}
	return map[string]string{
		"platform": "macos",
		"version":  version,
		"pretty":   pretty,
	}
}

func ChangeSignal() string {
	h := sha256.New()
	for _, c := range brewCellars {
		if fi, err := os.Stat(c); err == nil {
			fmt.Fprintf(h, "%s:%d;", c, fi.ModTime().UnixNano())
		}
	}
	if fi, err := os.Stat("/Library/LaunchDaemons"); err == nil {
		fmt.Fprintf(h, "ld:%d;", fi.ModTime().UnixNano())
	}
	return hex.EncodeToString(h.Sum(nil))
}

func processes() []Fact {
	out, err := exec.Command("ps", "-axww", "-o", "pid=,args=").Output()
	if err != nil {
		return nil
	}
	agg := map[string]*procInfo{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		pidStr, cmd, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}
		cmd = strings.TrimSpace(cmd)
		exe, _, _ := strings.Cut(cmd, " ")
		name := filepath.Base(exe)
		if name == "" || name == "." {
			continue
		}
		if len(cmd) > 300 {
			cmd = cmd[:300]
		}
		if p := agg[name]; p != nil {
			p.Count++
			continue
		}
		agg[name] = &procInfo{Count: 1, Pid: pid, Cmdline: cmd, Exe: exe}
	}
	return sortedFacts("process", agg)
}

func ports() []Fact {
	agg := map[string]*portInfo{}
	collect := func(proto string, args ...string) {
		out, err := exec.Command("lsof", args...).Output()
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(out), "\n") {
			f := strings.Fields(line)
			if len(f) < 9 || f[0] == "COMMAND" {
				continue
			}
			name := f[len(f)-1]
			if proto == "tcp" && len(f) >= 10 && f[len(f)-1] == "(LISTEN)" {
				name = f[len(f)-2]
			}
			colon := strings.LastIndexByte(name, ':')
			if colon < 0 {
				continue
			}
			port, err := strconv.ParseUint(name[colon+1:], 10, 16)
			if err != nil || port == 0 {
				continue
			}
			key := strconv.FormatUint(port, 10) + "/" + proto
			if agg[key] != nil {
				continue
			}
			pid, _ := strconv.Atoi(f[1])
			agg[key] = &portInfo{Addr: name[:colon], Pid: pid, Process: f[0]}
		}
	}
	collect("tcp", "-nP", "-iTCP", "-sTCP:LISTEN")
	collect("udp", "-nP", "-iUDP")
	return sortedFacts("port", agg)
}

type portInfo struct {
	Addr    string `json:"addr,omitempty"`
	Pid     int    `json:"pid,omitempty"`
	Process string `json:"process,omitempty"`
}

func packages() []Fact {
	agg := map[string]*packageInfo{}
	for _, cellar := range brewCellars {
		entries, err := os.ReadDir(cellar)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			version := ""
			if vers, err := os.ReadDir(filepath.Join(cellar, e.Name())); err == nil {
				for _, v := range vers {
					if v.IsDir() {
						version = v.Name()
						break
					}
				}
			}
			agg[e.Name()] = &packageInfo{Version: version}
		}
	}
	return sortedFacts("package", agg)
}

type unitInfo struct {
	Active string `json:"active,omitempty"`
	Pid    string `json:"pid,omitempty"`
}

func units() []Fact {
	out, err := exec.Command("launchctl", "list").Output()
	if err != nil {
		return nil
	}
	agg := map[string]*unitInfo{}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] == "PID" {
			continue
		}
		label := f[2]
		active := "inactive"
		if f[0] != "-" {
			active = "active"
		}
		agg[label] = &unitInfo{Active: active, Pid: f[0]}
	}
	return sortedFacts("unit", agg)
}
