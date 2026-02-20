//go:build windows

package main

import (
	"os"
	"os/exec"

	"golang.org/x/sys/windows"
)

func restartService() {
	cmd := exec.Command("cmd", "/c", "sc stop wakora & sc start wakora")
	cmd.SysProcAttr = &windows.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS}
	_ = cmd.Start()
}

func exitForRestart() {
	os.Exit(1)
}
