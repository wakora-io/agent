//go:build windows

package main

import (
	"os"
	"path/filepath"
)

var (
	defaultConfigDir = winDir()
	defaultLogFile   = filepath.Join(winDir(), "agent.log")
)

func winDir() string {
	if pd := os.Getenv("ProgramData"); pd != "" {
		return filepath.Join(pd, "Wakora")
	}
	return `C:\ProgramData\Wakora`
}
