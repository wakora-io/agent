//go:build !windows && !darwin

package main

import (
	"os"
	"os/exec"
)

func removePlatformService() {
	switch detectInit() {
	case "systemd":
		_ = exec.Command("systemctl", "stop", "wakora-agent").Run()
		_ = exec.Command("systemctl", "disable", "wakora-agent").Run()
		_ = os.Remove("/etc/systemd/system/wakora-agent.service")
		_ = exec.Command("systemctl", "daemon-reload").Run()
	case "openrc":
		_ = exec.Command("rc-service", "wakora-agent", "stop").Run()
		_ = exec.Command("rc-update", "del", "wakora-agent").Run()
		_ = os.Remove("/etc/init.d/wakora-agent")
	default:
		_ = exec.Command("service", "wakora-agent", "stop").Run()
		_ = exec.Command("update-rc.d", "-f", "wakora-agent", "remove").Run()
		_ = os.Remove("/etc/init.d/wakora-agent")
	}
}

func selfDeleteBinary(exe string) error {
	return os.Remove(exe)
}
