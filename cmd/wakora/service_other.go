//go:build !windows && !darwin

package main

import (
	"context"
	"fmt"
	"os"
)

func underServiceManager() bool { return false }

func runUnderServiceManager(context.Context, func(context.Context) error) error { return nil }

func runServiceCmd([]string) {
	fmt.Fprintln(os.Stderr, "service management is windows/macos-only; use systemd/openrc on this platform")
	os.Exit(2)
}
