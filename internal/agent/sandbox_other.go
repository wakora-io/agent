//go:build !linux

package agent

func EnsureSandboxHeadroom() bool { return false }
