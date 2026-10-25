//go:build linux

package discovery

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type kernelImage struct {
	Package       string `json:"package"`
	Version       string `json:"version"`
	Source        string `json:"source,omitempty"`
	SourceVersion string `json:"sourceVersion,omitempty"`
}

type kernelInfo struct {
	Release     string        `json:"release"`
	ProcVersion string        `json:"procVersion,omitempty"`
	Signature   string        `json:"signature,omitempty"`
	Container   bool          `json:"container,omitempty"`
	Running     *kernelImage  `json:"running,omitempty"`
	Installed   []kernelImage `json:"installed,omitempty"`
}

const kernelInstalledCap = 20

type rpmKernel struct {
	name, verRel, arch string
}

var apkFlavorRe = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)+)-([0-9]+)-(lts|virt|edge|rpi|stable)$`)

func kernelFact(pkgs []Fact) Fact {
	info := kernelFrom("/", pkgs, rpmKernelImages())
	payload, _ := json.Marshal(info)
	return Fact{Kind: "host", Key: "kernel", Payload: string(payload)}
}

func rpmKernelImages() []rpmKernel {
	if _, err := os.Stat("/var/lib/rpm"); err != nil {
		return nil
	}
	out, _ := exec.Command("rpm", "-q", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n",
		"kernel-core", "kernel", "kernel-default", "kernel-uek-core", "kernel-uek").Output()
	return parseRpmKernels(string(out))
}

func parseRpmKernels(out string) []rpmKernel {
	var all []rpmKernel
	core := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		parts := strings.Split(strings.TrimSpace(line), "\t")
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
			continue
		}
		all = append(all, rpmKernel{name: parts[0], verRel: parts[1], arch: parts[2]})
		if strings.HasSuffix(parts[0], "-core") {
			core[strings.TrimSuffix(parts[0], "-core")+"|"+parts[1]] = true
		}
	}
	var res []rpmKernel
	for _, k := range all {
		if core[k.name+"|"+k.verRel] {
			continue
		}
		res = append(res, k)
	}
	return res
}

func rpmRunning(k rpmKernel, release string) bool {
	if k.verRel+"."+k.arch == release || k.verRel == release {
		return true
	}
	i := strings.LastIndex(release, "-")
	if i <= 0 || strings.ContainsAny(release[i+1:], "0123456789") {
		return false
	}
	base := release[:i]
	return k.verRel == base || strings.HasPrefix(k.verRel, base+".")
}

func kernelFrom(root string, pkgs []Fact, rpms []rpmKernel) kernelInfo {
	info := kernelInfo{
		Release:     readTrim(filepath.Join(root, "proc/sys/kernel/osrelease"), 120),
		ProcVersion: readTrim(filepath.Join(root, "proc/version"), 400),
		Signature:   readTrim(filepath.Join(root, "proc/version_signature"), 200),
		Container:   containerRoot(root),
	}
	if info.Container {
		return info
	}
	running := map[string]bool{}
	for _, name := range []string{
		"linux-image-" + info.Release,
		"linux-image-unsigned-" + info.Release,
		"proxmox-kernel-" + info.Release + "-signed",
		"proxmox-kernel-" + info.Release,
		"pve-kernel-" + info.Release,
	} {
		running[name] = true
	}
	apk := apkFlavorRe.FindStringSubmatch(info.Release)
	for _, f := range pkgs {
		if f.Kind != "package" || !kernelImageName(f.Key) {
			continue
		}
		if len(rpms) > 0 && strings.HasPrefix(f.Key, "kernel") {
			continue
		}
		var p packageInfo
		if json.Unmarshal([]byte(f.Payload), &p) != nil {
			continue
		}
		img := kernelImage{Package: f.Key, Version: p.Version, Source: p.Source, SourceVersion: p.SourceVersion}
		if running[f.Key] && info.Running == nil {
			r := img
			info.Running = &r
		}
		if apk != nil && f.Key == "linux-"+apk[3] && info.Running == nil {
			info.Running = &kernelImage{Package: f.Key, Version: apk[1] + "-r" + apk[2]}
		}
		info.Installed = append(info.Installed, img)
	}
	for _, k := range rpms {
		img := kernelImage{Package: k.name, Version: k.verRel}
		if info.Running == nil && rpmRunning(k, info.Release) {
			r := img
			info.Running = &r
		}
		info.Installed = append(info.Installed, img)
	}
	sort.Slice(info.Installed, func(i, j int) bool { return info.Installed[i].Package < info.Installed[j].Package })
	if len(info.Installed) > kernelInstalledCap {
		info.Installed = info.Installed[len(info.Installed)-kernelInstalledCap:]
	}
	return info
}

func kernelImageName(name string) bool {
	for _, prefix := range []string{"linux-image-", "proxmox-kernel-", "pve-kernel-"} {
		rest, ok := strings.CutPrefix(name, prefix)
		if !ok {
			continue
		}
		rest = strings.TrimPrefix(rest, "unsigned-")
		return rest != "" && rest[0] >= '0' && rest[0] <= '9' && strings.Contains(rest, "-")
	}
	switch name {
	case "kernel-core", "kernel", "linux-lts", "linux-virt", "linux-edge", "linux-rpi", "linux-stable":
		return true
	}
	return false
}

func readTrim(path string, max int) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(b))
	if len(s) > max {
		s = s[:max]
	}
	return s
}

func containerRoot(root string) bool {
	if b, err := os.ReadFile(filepath.Join(root, "run/systemd/container")); err == nil && strings.TrimSpace(string(b)) != "" {
		return true
	}
	if b, err := os.ReadFile(filepath.Join(root, "proc/1/environ")); err == nil {
		for _, kv := range strings.Split(string(b), "\x00") {
			if strings.HasPrefix(kv, "container=") && len(kv) > len("container=") {
				return true
			}
		}
	}
	if _, err := os.Stat(filepath.Join(root, ".dockerenv")); err == nil {
		return true
	}
	return false
}
