//go:build linux

package discovery

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseDpkgStatusSource(t *testing.T) {
	status := strings.Join([]string{
		"Package: libc6",
		"Status: install ok installed",
		"Source: glibc",
		"Version: 2.41-12+deb13u3",
		"",
		"Package: linux-image-6.1.0-90-amd64",
		"Status: install ok installed",
		"Source: linux-signed-amd64 (6.1.300+1)",
		"Version: 6.1.300-1",
		"",
		"Package: curl",
		"Status: install ok installed",
		"Version: 8.14.1-2",
		"",
		"Package: removed-one",
		"Status: deinstall ok config-files",
		"Version: 1.0",
		"",
	}, "\n")
	facts := parseDpkgStatus(strings.NewReader(status))
	got := map[string]string{}
	for _, f := range facts {
		got[f.Key] = f.Payload
	}
	if len(got) != 3 {
		t.Fatalf("want 3 installed packages, got %v", got)
	}
	if got["libc6"] != `{"version":"2.41-12+deb13u3","source":"glibc"}` {
		t.Fatalf("libc6: %s", got["libc6"])
	}
	if got["linux-image-6.1.0-90-amd64"] != `{"version":"6.1.300-1","source":"linux-signed-amd64","sourceVersion":"6.1.300+1"}` {
		t.Fatalf("kernel image: %s", got["linux-image-6.1.0-90-amd64"])
	}
	if got["curl"] != `{"version":"8.14.1-2"}` {
		t.Fatalf("curl: %s", got["curl"])
	}
}

func TestParseRpmListSource(t *testing.T) {
	out := "kernel-core\t5.14.0-900.1.1.el9_9\tkernel-5.14.0-900.1.1.el9_9.src.rpm\n" +
		"glibc\t2.34-200.el9\tglibc-2.34-200.el9.src.rpm\n" +
		"gpg-pubkey\tabcdef01-12345678\t(none)\n"
	facts := parseRpmList(out)
	got := map[string]string{}
	for _, f := range facts {
		got[f.Key] = f.Payload
	}
	if got["kernel-core"] != `{"version":"5.14.0-900.1.1.el9_9","source":"kernel"}` {
		t.Fatalf("kernel-core: %s", got["kernel-core"])
	}
	if got["glibc"] != `{"version":"2.34-200.el9"}` {
		t.Fatalf("glibc: %s", got["glibc"])
	}
	if got["gpg-pubkey"] != `{"version":"abcdef01-12345678"}` {
		t.Fatalf("gpg-pubkey: %s", got["gpg-pubkey"])
	}
}

func TestParseApkDBOrigin(t *testing.T) {
	facts := parseApkDB("P:libssl3\nV:3.5.9-r0\no:openssl\n\nP:openssl\nV:3.5.9-r0\no:openssl\n")
	if facts[0].Payload != `{"version":"3.5.9-r0","source":"openssl"}` || facts[1].Payload != `{"version":"3.5.9-r0"}` {
		t.Fatalf("origin: %+v", facts)
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func pkgFact(name, payload string) Fact {
	return Fact{Kind: "package", Key: name, Payload: payload}
}

func TestKernelFromHost(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "proc/sys/kernel/osrelease"), "7.9.1-30-pve\n")
	writeFile(t, filepath.Join(root, "proc/version"), "Linux version 7.9.1-30-pve (build@example) #1 SMP PREEMPT_DYNAMIC PMX 7.9.1-30 (2030-01-01T00:00Z)\n")
	pkgs := []Fact{
		pkgFact("proxmox-kernel-7.9.1-30-pve-signed", `{"version":"7.9.1-30"}`),
		pkgFact("proxmox-kernel-7.9.1-41-pve-signed", `{"version":"7.9.1-41"}`),
		pkgFact("proxmox-kernel-helper", `{"version":"9.0.0"}`),
		pkgFact("proxmox-kernel-7.9", `{"version":"7.9.1-41"}`),
		pkgFact("curl", `{"version":"8.0"}`),
	}
	k := kernelFrom(root, pkgs, nil)
	if k.Release != "7.9.1-30-pve" || k.Container {
		t.Fatalf("release/container: %+v", k)
	}
	if !strings.Contains(k.ProcVersion, "PMX 7.9.1-30") {
		t.Fatalf("procVersion: %q", k.ProcVersion)
	}
	if k.Running == nil || k.Running.Package != "proxmox-kernel-7.9.1-30-pve-signed" || k.Running.Version != "7.9.1-30" {
		t.Fatalf("running: %+v", k.Running)
	}
	if len(k.Installed) != 2 {
		t.Fatalf("installed images only, got %+v", k.Installed)
	}
}

func TestKernelFromContainer(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "proc/sys/kernel/osrelease"), "7.9.1-30-pve\n")
	writeFile(t, filepath.Join(root, "run/systemd/container"), "lxc\n")
	k := kernelFrom(root, []Fact{pkgFact("linux-image-6.1.0-90-amd64", `{"version":"6.1.300-1"}`)}, []rpmKernel{{name: "kernel-core", verRel: "5.14.0-900.el9", arch: "x86_64"}})
	if !k.Container || k.Running != nil || len(k.Installed) != 0 {
		t.Fatalf("container must report the host release only: %+v", k)
	}
	b, _ := json.Marshal(k)
	if strings.Contains(string(b), "installed") {
		t.Fatalf("container payload: %s", b)
	}
}

func TestParseRpmKernelsDropsTheMetaPackage(t *testing.T) {
	out := "kernel-core\t5.14.0-900.1.1.el9_9\tx86_64\n" +
		"kernel\t5.14.0-900.1.1.el9_9\tx86_64\n" +
		"kernel-core\t5.14.0-910.2.1.el9_9\tx86_64\n" +
		"package kernel-default is not installed\n" +
		"kernel-uek\t6.12.0-100.10.1.el9uek\tx86_64\n"
	got := parseRpmKernels(out)
	want := []rpmKernel{
		{name: "kernel-core", verRel: "5.14.0-900.1.1.el9_9", arch: "x86_64"},
		{name: "kernel-core", verRel: "5.14.0-910.2.1.el9_9", arch: "x86_64"},
		{name: "kernel-uek", verRel: "6.12.0-100.10.1.el9uek", arch: "x86_64"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("row %d: got %+v want %+v", i, got[i], want[i])
		}
	}
}

func TestKernelFromRpmHost(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "proc/sys/kernel/osrelease"), "5.14.0-900.1.1.el9_9.x86_64\n")
	rpms := []rpmKernel{
		{name: "kernel-core", verRel: "5.14.0-890.5.1.el9_9", arch: "x86_64"},
		{name: "kernel-core", verRel: "5.14.0-900.1.1.el9_9", arch: "x86_64"},
		{name: "kernel-core", verRel: "5.14.0-910.2.1.el9_9", arch: "x86_64"},
	}
	k := kernelFrom(root, []Fact{pkgFact("kernel-core", `{"version":"5.14.0-910.2.1.el9_9","source":"kernel"}`)}, rpms)
	if k.Running == nil || k.Running.Package != "kernel-core" || k.Running.Version != "5.14.0-900.1.1.el9_9" {
		t.Fatalf("running: %+v", k.Running)
	}
	if len(k.Installed) != 3 {
		t.Fatalf("every installed image once, got %+v", k.Installed)
	}
}

func TestKernelFromSuseHost(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "proc/sys/kernel/osrelease"), "6.4.0-150600.40.7-default\n")
	rpms := []rpmKernel{
		{name: "kernel-default", verRel: "6.4.0-150600.40.7.1", arch: "x86_64"},
		{name: "kernel-default", verRel: "6.4.0-150600.40.70.1", arch: "x86_64"},
	}
	k := kernelFrom(root, nil, rpms)
	if k.Running == nil || k.Running.Version != "6.4.0-150600.40.7.1" {
		t.Fatalf("running: %+v", k.Running)
	}
}

func TestKernelFromAlpineHost(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "proc/sys/kernel/osrelease"), "6.12.300-0-lts\n")
	k := kernelFrom(root, []Fact{pkgFact("linux-lts", `{"version":"6.12.310-r0"}`), pkgFact("curl", `{"version":"8.0-r0"}`)}, nil)
	if k.Running == nil || k.Running.Package != "linux-lts" || k.Running.Version != "6.12.300-r0" {
		t.Fatalf("running is the booted build, not the upgraded package: %+v", k.Running)
	}
	if len(k.Installed) != 1 || k.Installed[0].Version != "6.12.310-r0" {
		t.Fatalf("installed: %+v", k.Installed)
	}
}

func TestKernelFromUbuntuIgnoresApkFlavours(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "proc/sys/kernel/osrelease"), "6.8.0-900-generic\n")
	k := kernelFrom(root, []Fact{pkgFact("linux-generic", `{"version":"6.8.0.900.900"}`)}, nil)
	if k.Running != nil || len(k.Installed) != 0 {
		t.Fatalf("an Ubuntu metapackage is not a running image: %+v", k)
	}
}

func TestKernelImageName(t *testing.T) {
	for name, want := range map[string]bool{
		"linux-image-6.8.0-500-generic":          true,
		"linux-image-unsigned-6.8.0-500-generic": true,
		"linux-image-amd64":                      false,
		"linux-image-generic":                    false,
		"proxmox-kernel-7.9.1-30-pve-signed":     true,
		"proxmox-kernel-7.9":                     false,
		"proxmox-kernel-helper":                  false,
		"pve-kernel-6.2.16-20-pve":               true,
		"kernel-core":                            true,
		"linux-lts":                              true,
		"linux-virt":                             true,
		"linux-generic":                          false,
		"linux-firmware":                         false,
	} {
		if kernelImageName(name) != want {
			t.Fatalf("kernelImageName(%q) != %v", name, want)
		}
	}
}
