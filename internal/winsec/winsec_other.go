//go:build !windows

package winsec

func ProtectDir(path string) error { return nil }
