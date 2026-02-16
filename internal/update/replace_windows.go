//go:build windows

package update

import "os"

func assetNames() (bin, sum string) {
	return "/wakora.exe", "/wakora.exe.sha256"
}

// A running .exe cannot be overwritten, but Windows permits renaming it.
// Move the live binary aside, then move the new one into place; the stale
// .old is cleared on next start (see CleanupOld).
func replaceBinary(tmp, target string) error {
	old := target + ".old"
	_ = os.Remove(old)
	if err := os.Rename(target, old); err != nil {
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Rename(old, target)
		return err
	}
	return nil
}

func CleanupOld() {
	if exe, err := os.Executable(); err == nil {
		_ = os.Remove(exe + ".old")
	}
}
