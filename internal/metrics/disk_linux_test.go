//go:build linux

package metrics

import (
	"syscall"
	"testing"
)

func TestFsReadOnlyReadsTheMountFlag(t *testing.T) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(t.TempDir(), &st); err != nil {
		t.Skip("statfs unavailable")
	}
	if fsReadOnly(&st) {
		t.Fatal("a writable temp dir must not read as read-only")
	}
	ro := st
	ro.Flags |= syscall.MS_RDONLY
	if !fsReadOnly(&ro) {
		t.Fatal("ST_RDONLY set must read as read-only")
	}
}
