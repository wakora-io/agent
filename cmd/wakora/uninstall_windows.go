//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

func removePlatformService() {
	_ = uninstallService()
}

func apmApplied(string) bool { return false }

func selfDeleteBinary(exe string) error {
	cmd := exec.Command("cmd", "/c", "ping 127.0.0.1 -n 3 > nul & del /f /q \""+exe+"\"")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x00000008}
	return cmd.Start()
}
