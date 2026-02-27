//go:build windows

package update

import (
	"os"
	"runtime"
)

func assetNames() (bin, sum string) {
	if runtime.GOARCH != "amd64" {
		base := "/wakora-windows-" + runtime.GOARCH + ".exe"
		return base, base + ".sha256"
	}
	return "/wakora.exe", "/wakora.exe.sha256"
}

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
