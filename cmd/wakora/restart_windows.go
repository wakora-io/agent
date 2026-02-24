//go:build windows

package main

import (
	"log"
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
	if spawnRestartHelper() && requestSelfStop() {
		log.Print("graceful service restart requested (helper spawned)")
		return
	}
	os.Exit(1)
}

func spawnRestartHelper() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	cmd := exec.Command(exe, "service", "await-restart")
	cmd.SysProcAttr = &windows.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
	}
	return cmd.Start() == nil
}
