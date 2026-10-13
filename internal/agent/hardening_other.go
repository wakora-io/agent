//go:build !linux

package agent

func EnsureUnitHardening(stateDir string) bool { return false }
