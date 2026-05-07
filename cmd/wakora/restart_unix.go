//go:build !windows && !darwin

package main

import (
	"os"
	"os/exec"
	"syscall"
)

func detectInit() string {
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		return "systemd"
	}
	if _, err := os.Stat("/run/openrc"); err == nil {
		return "openrc"
	}
	return "sysvinit"
}

func restartService() {
	switch detectInit() {
	case "systemd":
		_ = exec.Command("systemctl", "restart", "wakora-agent").Run()
	case "openrc":
		_ = exec.Command("rc-service", "wakora-agent", "restart").Run()
	default:
		_ = exec.Command("service", "wakora-agent", "restart").Run()
	}
}

func exitForRestart() {

	if detectInit() == "sysvinit" {
		cmd := exec.Command("sh", "-c",
			"sleep 1; /etc/init.d/wakora-agent restart 2>/dev/null || service wakora-agent restart")
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		_ = cmd.Start()
	}
	os.Exit(0)
}
