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

func TestParseMountReadOnlyReadsTheInitViewLastMountWins(t *testing.T) {
	table := "/dev/drbd1003 / ext4 rw,relatime,stripe=4 0 0\n" +
		"proc /proc proc rw,nosuid 0 0\n" +
		"/dev/sda1 /boot ext4 rw,relatime 0 0\n" +
		"/dev/sda1 /boot ext4 ro,relatime 0 0\n" +
		"/dev/sdb1 /mnt/data\\040disk xfs ro,relatime 0 0\n" +
		"/dev/sdc1 /media/usb vfat ro 0 0\n"
	got := parseMountReadOnly(table)
	if got["/"] {
		t.Fatal("init sees / as rw, the agent must not report its own sandbox view")
	}
	if !got["/boot"] {
		t.Fatal("the later mount at a path is the one processes see")
	}
	if !got["/mnt/data disk"] {
		t.Fatal("escaped space in the mountpoint must be decoded")
	}
	if _, ok := got["/proc"]; ok {
		t.Fatal("pseudo filesystems are not disks")
	}
	if _, ok := got["/media/usb"]; !ok {
		t.Fatal("vfat rides the table; the watch filter decides separately")
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
