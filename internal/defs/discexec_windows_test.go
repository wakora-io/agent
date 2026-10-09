//go:build windows

package defs

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsExecRefusesBinariesOutsideAdminRoots(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "node.exe")
	if err := os.WriteFile(exe, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := trustedCmd(context.Background(), exe); err == nil {
		t.Fatal("a binary a plain user can replace must never run as the service account")
	}
}

func TestWindowsExecRefusesProgramData(t *testing.T) {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		t.Skip("no ProgramData on this box")
	}
	if _, err := trustedCmd(context.Background(), filepath.Join(pd, "anyone", "node.exe")); err == nil {
		t.Fatal("plain users create folders under ProgramData - a binary there must not run as the service account")
	}
}

func TestFileVersionReadsTheResourceWithoutRunningIt(t *testing.T) {
	root := os.Getenv("SystemRoot")
	if root == "" {
		t.Skip("no SystemRoot on this box")
	}
	exe := filepath.Join(root, "System32", "where.exe")
	if _, err := os.Stat(exe); err != nil {
		t.Skip("where.exe is not present")
	}
	if v := fileVersion(exe); strings.Count(v, ".") != 2 || strings.HasPrefix(v, "0.") {
		t.Fatalf("a system binary carries a version resource, got %q", v)
	}
	fake := filepath.Join(t.TempDir(), "node.exe")
	if err := os.WriteFile(fake, []byte("echo v99.0.0"), 0o644); err != nil {
		t.Fatal(err)
	}
	if v := fileVersion(fake); v != "" {
		t.Fatalf("a file without a version resource must read as unknown, got %q", v)
	}
}

func TestWindowsExecAllowsAdminRoots(t *testing.T) {
	root := os.Getenv("SystemRoot")
	if root == "" {
		t.Skip("no SystemRoot on this box")
	}
	exe := filepath.Join(root, "System32", "where.exe")
	if _, err := os.Stat(exe); err != nil {
		t.Skip("where.exe is not present")
	}
	if _, err := trustedCmd(context.Background(), exe); err != nil {
		t.Fatalf("a binary under an administrator-only root must run: %v", err)
	}
}
