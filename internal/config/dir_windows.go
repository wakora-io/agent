//go:build windows

package config

import (
	"os"
	"path/filepath"
)

var defaultDir = windowsDir()

func windowsDir() string {
	if pd := os.Getenv("ProgramData"); pd != "" {
		return filepath.Join(pd, "Wakora")
	}
	return `C:\ProgramData\Wakora`
}
