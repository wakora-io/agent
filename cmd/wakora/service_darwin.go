//go:build darwin

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

const launchdLabel = "io.wakora.agent"

const plistPath = "/Library/LaunchDaemons/" + launchdLabel + ".plist"

func underServiceManager() bool { return false }

func runUnderServiceManager(context.Context, func(context.Context) error) error { return nil }

func runServiceCmd(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: wakora service <install|uninstall|start|stop>")
		os.Exit(2)
	}
	switch args[0] {
	case "install":
		if err := installLaunchd(); err != nil {
			fmt.Fprintf(os.Stderr, "install: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "wakora launchd daemon installed and started")
	case "uninstall":
		_ = exec.Command("launchctl", "bootout", "system/"+launchdLabel).Run()
		if err := os.Remove(plistPath); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "uninstall: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "wakora launchd daemon removed")
	case "start":
		_ = exec.Command("launchctl", "kickstart", "system/"+launchdLabel).Run()
	case "stop":
		_ = exec.Command("launchctl", "kill", "TERM", "system/"+launchdLabel).Run()
	default:
		fmt.Fprintf(os.Stderr, "unknown service command %q\n", args[0])
		os.Exit(2)
	}
}

func checkServiceExePath(exe string) error {
	p, err := filepath.EvalSymlinks(exe)
	if err != nil {
		p = exe
	}
	for {
		fi, err := os.Stat(p)
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("cannot read ownership of %s", p)
		}
		if st.Uid != 0 || fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s is not root-owned and root-writable-only: registering the service here would let its owner replace what launchd starts as root - copy the binary to /usr/local/bin and install from there", p)
		}
		parent := filepath.Dir(p)
		if parent == p {
			return nil
		}
		p = parent
	}
}

func installLaunchd() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := checkServiceExePath(exe); err != nil {
		return err
	}
	if err := os.MkdirAll(defaultConfigDir, 0o700); err != nil {
		return err
	}
	plist := strings.NewReplacer("{{EXE}}", exe, "{{LOG}}", defaultLogFile, "{{LABEL}}", launchdLabel).Replace(plistTemplate)
	if err := os.WriteFile(plistPath, []byte(plist), 0o644); err != nil {
		return err
	}
	_ = exec.Command("launchctl", "bootout", "system/"+launchdLabel).Run()
	if err := exec.Command("launchctl", "bootstrap", "system", plistPath).Run(); err != nil {
		return err
	}
	return exec.Command("launchctl", "enable", "system/"+launchdLabel).Run()
}

const plistTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{{LABEL}}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{{EXE}}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ProcessType</key>
  <string>Background</string>
  <key>StandardErrorPath</key>
  <string>{{LOG}}</string>
  <key>StandardOutPath</key>
  <string>{{LOG}}</string>
</dict>
</plist>
`
