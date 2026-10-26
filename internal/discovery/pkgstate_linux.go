//go:build linux

package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type pkgState struct {
	updates map[string]string
	orphans map[string]bool
}

const pkgStateTTL = 6 * time.Hour

var pkgStateCache struct {
	sync.Mutex
	key   string
	at    time.Time
	state *pkgState
}

var (
	aptUpgradableRe = regexp.MustCompile(`^([^/\s]+)/\S+\s+(\S+)\s+\S+\s+\[upgradable from:`)
	apkNameVerRe    = regexp.MustCompile(`^(.+)-([^-]+-r[0-9]+)$`)
)

func pkgDBSignal() string {
	var b strings.Builder
	if fi, err := os.Stat("/var/lib/dpkg/status"); err == nil {
		fmt.Fprintf(&b, "dpkg:%d:%d;", fi.ModTime().UnixNano(), fi.Size())
	}
	b.WriteString(rpmSignal("/var/lib/rpm"))
	if fi, err := os.Stat("/lib/apk/db/installed"); err == nil {
		fmt.Fprintf(&b, "apk:%d:%d;", fi.ModTime().UnixNano(), fi.Size())
	}
	return b.String()
}

func currentPkgState() *pkgState {
	key := pkgDBSignal()
	pkgStateCache.Lock()
	defer pkgStateCache.Unlock()
	if pkgStateCache.state != nil && pkgStateCache.key == key && time.Since(pkgStateCache.at) < pkgStateTTL {
		return pkgStateCache.state
	}
	st, err := queryPkgState()
	if err != nil {
		return pkgStateCache.state
	}
	pkgStateCache.key, pkgStateCache.at, pkgStateCache.state = key, time.Now(), st
	return st
}

func pkgRun(name string, args ...string) (string, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return string(out), ee.ExitCode(), nil
		}
		return "", -1, err
	}
	return string(out), 0, nil
}

func queryPkgState() (*pkgState, error) {
	switch {
	case statOK("/var/lib/dpkg/status"):
		return aptPkgState()
	case statOK("/var/lib/rpm"):
		if _, err := exec.LookPath("zypper"); err == nil {
			return zypperPkgState()
		}
		return dnfPkgState()
	case statOK("/lib/apk/db/installed"):
		return apkPkgState()
	}
	return nil, fmt.Errorf("no package manager")
}

func aptPkgState() (*pkgState, error) {
	lists, _ := filepath.Glob("/var/lib/apt/lists/*_Packages")
	if len(lists) == 0 {
		return nil, fmt.Errorf("no apt metadata")
	}
	up, rc, err := pkgRun("apt", "list", "--upgradable")
	if err != nil || rc != 0 {
		return nil, fmt.Errorf("apt list --upgradable: rc %d %v", rc, err)
	}
	inst, rc, err := pkgRun("apt", "list", "--installed")
	if err != nil || rc != 0 {
		return nil, fmt.Errorf("apt list --installed: rc %d %v", rc, err)
	}
	return &pkgState{updates: parseAptUpgradable(up), orphans: parseAptLocal(inst)}, nil
}

func parseAptUpgradable(out string) map[string]string {
	res := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if m := aptUpgradableRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			res[m[1]] = m[2]
		}
	}
	return res
}

func parseAptLocal(out string) map[string]bool {
	res := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasSuffix(line, "[installed,local]") {
			continue
		}
		if name, _, ok := strings.Cut(line, "/"); ok && name != "" {
			res[name] = true
		}
	}
	return res
}

func dnfPkgState() (*pkgState, error) {
	bin := "dnf"
	if _, err := exec.LookPath(bin); err != nil {
		bin = "yum"
		if _, err := exec.LookPath(bin); err != nil {
			return nil, fmt.Errorf("no dnf or yum")
		}
	}
	up, rc, err := pkgRun(bin, "-C", "-q", "check-update")
	if err != nil || (rc != 0 && rc != 100) {
		return nil, fmt.Errorf("%s check-update: rc %d %v", bin, rc, err)
	}
	extras := "--extras"
	if bin == "yum" {
		extras = "extras"
	}
	ex, rc, err := pkgRun(bin, "-C", "-q", "list", extras)
	if err != nil || rc != 0 {
		return nil, fmt.Errorf("%s list extras: rc %d %v", bin, rc, err)
	}
	return &pkgState{updates: parseDnfCheckUpdate(up), orphans: parseDnfExtras(ex)}, nil
}

func dnfName(nameArch string) string {
	if i := strings.LastIndex(nameArch, "."); i > 0 {
		return nameArch[:i]
	}
	return nameArch
}

func dnfRows(out string) [][]string {
	var rows [][]string
	pending := ""
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "Obsoleting") {
			break
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if pending != "" {
				rows = append(rows, append([]string{pending}, f...))
				pending = ""
			}
			continue
		}
		if len(f) == 1 && strings.Contains(f[0], ".") {
			pending = f[0]
			continue
		}
		pending = ""
		if len(f) >= 2 && strings.Contains(f[0], ".") {
			rows = append(rows, f)
		}
	}
	return rows
}

func parseDnfCheckUpdate(out string) map[string]string {
	res := map[string]string{}
	for _, f := range dnfRows(out) {
		res[dnfName(f[0])] = f[1]
	}
	return res
}

func parseDnfExtras(out string) map[string]bool {
	res := map[string]bool{}
	for _, f := range dnfRows(out) {
		res[dnfName(f[0])] = true
	}
	return res
}

func zypperPkgState() (*pkgState, error) {
	up, rc, err := pkgRun("zypper", "-n", "--no-refresh", "-q", "list-updates")
	if err != nil || rc != 0 {
		return nil, fmt.Errorf("zypper list-updates: rc %d %v", rc, err)
	}
	or, rc, err := pkgRun("zypper", "-n", "--no-refresh", "-q", "packages", "--orphaned")
	if err != nil || rc != 0 {
		return nil, fmt.Errorf("zypper packages --orphaned: rc %d %v", rc, err)
	}
	return &pkgState{updates: parseZypperUpdates(up), orphans: parseZypperOrphans(or)}, nil
}

func zypperRows(out string) [][]string {
	var rows [][]string
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "|") {
			continue
		}
		cols := strings.Split(line, "|")
		for i := range cols {
			cols[i] = strings.TrimSpace(cols[i])
		}
		if cols[0] == "S" || strings.HasPrefix(cols[0], "-") {
			continue
		}
		rows = append(rows, cols)
	}
	return rows
}

func parseZypperUpdates(out string) map[string]string {
	res := map[string]string{}
	for _, c := range zypperRows(out) {
		if len(c) >= 5 && c[2] != "" && c[4] != "" {
			res[c[2]] = c[4]
		}
	}
	return res
}

func parseZypperOrphans(out string) map[string]bool {
	res := map[string]bool{}
	for _, c := range zypperRows(out) {
		if len(c) >= 3 && c[2] != "" {
			res[c[2]] = true
		}
	}
	return res
}

func apkPkgState() (*pkgState, error) {
	idx, _ := filepath.Glob("/var/cache/apk/APKINDEX.*.tar.gz")
	if len(idx) == 0 {
		return nil, fmt.Errorf("no apk index")
	}
	up, rc, err := pkgRun("apk", "version", "-l", "<")
	if err != nil || rc != 0 {
		return nil, fmt.Errorf("apk version: rc %d %v", rc, err)
	}
	or, rc, err := pkgRun("apk", "list", "-O")
	if err != nil || rc != 0 {
		return nil, fmt.Errorf("apk list -O: rc %d %v", rc, err)
	}
	return &pkgState{updates: parseApkVersion(up), orphans: parseApkOrphans(or)}, nil
}

func parseApkVersion(out string) map[string]string {
	res := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[1] != "<" {
			continue
		}
		if m := apkNameVerRe.FindStringSubmatch(f[0]); m != nil {
			res[m[1]] = f[2]
		}
	}
	return res
}

func parseApkOrphans(out string) map[string]bool {
	res := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if m := apkNameVerRe.FindStringSubmatch(f[0]); m != nil {
			res[m[1]] = true
		}
	}
	return res
}

func withPkgState(facts []Fact, st *pkgState) []Fact {
	if st == nil {
		return facts
	}
	for i, f := range facts {
		up, hasUp := st.updates[f.Key]
		orphan := st.orphans[f.Key]
		if !hasUp && !orphan {
			continue
		}
		var p packageInfo
		if json.Unmarshal([]byte(f.Payload), &p) != nil {
			continue
		}
		if hasUp && up != p.Version {
			p.Update = up
		}
		p.Orphan = orphan
		if b, err := json.Marshal(p); err == nil {
			facts[i].Payload = string(b)
		}
	}
	return facts
}
