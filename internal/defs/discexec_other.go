//go:build !linux

package defs

import (
	"context"
	"os/exec"
)

func trustedCmd(ctx context.Context, path string, args ...string) (*exec.Cmd, error) {
	return exec.CommandContext(ctx, path, args...), nil
}

func trustedOutput(ctx context.Context, path string, args ...string) ([]byte, error) {
	cmd, err := trustedCmd(ctx, path, args...)
	if err != nil {
		return nil, err
	}
	return cmd.Output()
}
