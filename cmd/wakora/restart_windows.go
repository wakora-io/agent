//go:build windows

package main

import (
	"os"
	"os/exec"

	"golang.org/x/sys/windows"
)

// Restart via a detached shell so the command survives our own stop.
func restartService() {
	cmd := exec.Command("cmd", "/c", "sc stop wakora & sc start wakora")
	cmd.SysProcAttr = &windows.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS}
	_ = cmd.Start()
}

// Under SCM a non-zero exit triggers the configured recovery restart, which
// relaunches the freshly-swapped binary.
func exitForRestart() {
	os.Exit(1)
}
