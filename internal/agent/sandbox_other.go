//go:build !linux

package agent

func EnsureSandboxHeadroom(stateDir string) bool { return false }
