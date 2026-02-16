//go:build !windows

package main

import (
	"os"
	"os/exec"
)

func restartService() {
	_ = exec.Command("systemctl", "restart", "wakora-agent").Run()
}

func exitForRestart() {
	os.Exit(0)
}
