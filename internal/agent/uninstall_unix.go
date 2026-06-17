//go:build !windows

package agent

import (
	"os"
	"os/exec"
	"syscall"
)

func spawnUninstall(dir string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		if run, e := exec.LookPath("systemd-run"); e == nil {
			cmd := exec.Command(run, "--scope", "--collect", "--quiet", exe, "uninstall", "--deregistered", "--config", dir)
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
			if cmd.Start() == nil {
				return nil
			}
		}
	}
	cmd := exec.Command(exe, "uninstall", "--deregistered", "--config", dir)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Start()
}
