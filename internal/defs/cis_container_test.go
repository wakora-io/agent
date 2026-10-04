//go:build linux

package defs

import (
	"os"
	"path/filepath"
	"testing"
)

func cisWrite(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCISContainerDetection(t *testing.T) {
	bare := t.TempDir()
	cisWrite(t, bare, "proc/1/environ", "PATH=/usr/bin\x00HOME=/\x00")
	if cisInContainer(bare) {
		t.Fatal("a host without container markers was read as a container")
	}

	lxc := t.TempDir()
	cisWrite(t, lxc, "run/systemd/container", "lxc\n")
	if !cisInContainer(lxc) {
		t.Fatal("systemd container marker not honored")
	}

	env := t.TempDir()
	cisWrite(t, env, "proc/1/environ", "PATH=/usr/bin\x00container=lxc\x00")
	if !cisInContainer(env) {
		t.Fatal("container= in the init environment not honored")
	}

	empty := t.TempDir()
	cisWrite(t, empty, "proc/1/environ", "container=\x00")
	if cisInContainer(empty) {
		t.Fatal("an empty container= value must not count")
	}

	docker := t.TempDir()
	cisWrite(t, docker, ".dockerenv", "")
	if !cisInContainer(docker) {
		t.Fatal(".dockerenv not honored")
	}
}

func TestCISAuditdMustRunNotJustExist(t *testing.T) {
	none := t.TempDir()
	if installed, running := cisAuditd(none); installed || running {
		t.Fatalf("no binary: installed=%v running=%v", installed, running)
	}

	dead := t.TempDir()
	cisWrite(t, dead, "sbin/auditd", "")
	cisWrite(t, dead, "proc/42/comm", "sshd\n")
	cisWrite(t, dead, "proc/self/comm", "auditd\n")
	if installed, running := cisAuditd(dead); !installed || running {
		t.Fatalf("installed but stopped: installed=%v running=%v", installed, running)
	}

	live := t.TempDir()
	cisWrite(t, live, "usr/sbin/auditd", "")
	cisWrite(t, live, "proc/42/comm", "sshd\n")
	cisWrite(t, live, "proc/731/comm", "auditd\n")
	if installed, running := cisAuditd(live); !installed || !running {
		t.Fatalf("running daemon not seen: installed=%v running=%v", installed, running)
	}
}
