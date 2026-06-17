//go:build darwin

package main

import (
	"os"
	"os/exec"
)

func removePlatformService() {
	_ = exec.Command("launchctl", "bootout", "system/"+launchdLabel).Run()
	_ = os.Remove(plistPath)
}

func selfDeleteBinary(exe string) error {
	return os.Remove(exe)
}
