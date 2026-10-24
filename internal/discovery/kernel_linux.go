//go:build linux

package discovery

import (
	"encoding/json"
	"os"
	"path/filepath"
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

func kernelFact(pkgs []Fact) Fact {
	info := kernelFrom("/", pkgs)
	payload, _ := json.Marshal(info)
	return Fact{Kind: "host", Key: "kernel", Payload: string(payload)}
}

func kernelFrom(root string, pkgs []Fact) kernelInfo {
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
	for _, f := range pkgs {
		if f.Kind != "package" || !kernelImageName(f.Key) {
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
	return name == "kernel-core" || name == "kernel"
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
