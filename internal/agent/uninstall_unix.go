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
	cmd := exec.Command(exe, "uninstall", "--deregistered", "--config", dir)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Start()
}
