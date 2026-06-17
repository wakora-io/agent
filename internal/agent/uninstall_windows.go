//go:build windows

package agent

import (
	"os"
	"os/exec"
)

func spawnUninstall(dir string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return exec.Command(exe, "uninstall", "--deregistered", "--config", dir).Start()
}
