//go:build !windows

package main

import "os/exec"

func restartService() {
	_ = exec.Command("systemctl", "restart", "wakora-agent").Run()
}
