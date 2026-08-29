//go:build linux

package defs

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestTrustedCmdRunsASystemBinaryAsIs(t *testing.T) {
	if _, err := os.Stat("/bin/true"); err != nil {
		t.Skip("no /bin/true here")
	}
	cmd, err := trustedCmd(context.Background(), "/bin/true")
	if err != nil {
		t.Fatalf("a system binary was refused: %v", err)
	}
	if cmd.SysProcAttr != nil && cmd.SysProcAttr.Credential != nil {
		t.Fatal("a root-owned system binary should run without dropping")
	}
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
}

func TestTrustedCmdRefusesABinaryOthersCanWrite(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to own the fixture")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "node")
	if err := os.WriteFile(p, []byte("#!/bin/sh\necho v99.0.0\n"), 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := trustedCmd(context.Background(), p); err == nil {
		t.Fatal("a world-writable binary was accepted for execution as root")
	}
}

func TestTrustedCmdDropsToTheOwnerOfAUserBinary(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to chown the fixture")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "node")
	if err := os.WriteFile(p, []byte("#!/bin/sh\necho v18.19.0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(p, 4242, 4242); err != nil {
		t.Skipf("cannot chown here: %v", err)
	}
	cmd, err := trustedCmd(context.Background(), p)
	if err != nil {
		t.Fatalf("a user-owned binary should still run, dropped: %v", err)
	}
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.Credential == nil {
		t.Fatal("a user-owned binary was about to run with agent privileges")
	}
	if got := cmd.SysProcAttr.Credential.Uid; got != 4242 {
		t.Fatalf("dropped to uid %d, want the file owner 4242", got)
	}
}

func TestTrustedCmdRefusesARootBinaryInAWritableDirectory(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to own the fixture")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "php-fpm")
	if err := os.WriteFile(p, []byte("#!/bin/sh\ntrue\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := trustedCmd(context.Background(), p); err == nil {
		t.Fatal("a root-owned binary in a world-writable directory was accepted")
	}
}
