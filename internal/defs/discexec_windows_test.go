//go:build windows

package defs

import (
	"context"
	"os"
	"path/filepath"
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
