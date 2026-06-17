//go:build !windows && !darwin

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

func apmApplied(apmDir string) bool {
	for _, g := range []string{
		"/etc/php/*/fpm/conf.d/*.ini",
		"/etc/php/*/apache2/conf.d/*.ini",
		"/etc/php/*/cli/conf.d/*.ini",
		"/etc/php*/conf.d/*.ini",
		"/etc/php.d/*.ini",
		"/etc/opt/remi/php*/php.d/*.ini",
	} {
		matches, _ := filepath.Glob(g)
		for _, f := range matches {
			data, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				t := strings.TrimSpace(line)
				if t == "" || t[0] == ';' || t[0] == '#' {
					continue
				}
				if strings.Contains(t, apmDir) {
					return true
				}
			}
		}
	}
	return false
}
