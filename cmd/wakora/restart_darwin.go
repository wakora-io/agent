//go:build darwin

package main

import (
	"os"
	"os/exec"
)

func restartService() {
	_ = exec.Command("launchctl", "kickstart", "-k", "system/"+launchdLabel).Run()
}

func exitForRestart() {
	os.Exit(0)
}
