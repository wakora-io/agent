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

func TestReadOnlyWatchedSkipsOnlyTheEfiClass(t *testing.T) {
	for _, fs := range []string{"ext4", "xfs", "btrfs", "zfs", "ntfs", "ntfs3", "fuseblk", "exfat"} {
		if !readOnlyWatched(fs) {
			t.Fatalf("%s holds data and must be judged", fs)
		}
	}
	if readOnlyWatched("vfat") {
		t.Fatal("vfat is the efi system partition, a read-only one is not an incident")
	}
}
