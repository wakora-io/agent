//go:build windows

package main

import "os/exec"

func restartService() {
	_ = exec.Command("sc", "stop", "wakora").Run()
	_ = exec.Command("sc", "start", "wakora").Run()
}
