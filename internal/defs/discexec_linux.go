//go:build linux

package defs

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

func trustedCmd(ctx context.Context, path string, args ...string) (*exec.Cmd, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("defs: cannot read ownership of %s", path)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("defs: %s is writable by others, refusing to run it", path)
	}
	cmd := exec.CommandContext(ctx, path, args...)
	if st.Uid == 0 && parentsTrusted(path) {
		return cmd, nil
	}
	if st.Uid == 0 {
		return nil, fmt.Errorf("defs: %s sits in a directory others can write, refusing to run it", path)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: st.Uid, Gid: st.Gid, NoSetGroups: true},
	}
	return cmd, nil
}

func trustedOutput(ctx context.Context, path string, args ...string) ([]byte, error) {
	cmd, err := trustedCmd(ctx, path, args...)
	if err != nil {
		return nil, err
	}
	return cmd.Output()
}

func parentsTrusted(path string) bool {
	dir := filepath.Dir(path)
	for {
		fi, err := os.Stat(dir)
		if err != nil {
			return false
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || fi.Mode().Perm()&0o022 != 0 {
			return false
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return true
		}
		dir = parent
	}
}
