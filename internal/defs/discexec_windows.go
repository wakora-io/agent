//go:build windows

package defs

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func adminOwnedRoots() []string {
	var out []string
	for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "ProgramData", "SystemRoot"} {
		if v := os.Getenv(env); v != "" {
			out = append(out, strings.ToLower(filepath.Clean(v))+string(filepath.Separator))
		}
	}
	return out
}

func trustedCmd(ctx context.Context, path string, args ...string) (*exec.Cmd, error) {
	full := strings.ToLower(filepath.Clean(path))
	for _, root := range adminOwnedRoots() {
		if strings.HasPrefix(full, root) {
			return exec.CommandContext(ctx, path, args...), nil
		}
	}
	return nil, fmt.Errorf("defs: %s sits outside the directories only administrators can write, refusing to run it as the service account", path)
}

func trustedOutput(ctx context.Context, path string, args ...string) ([]byte, error) {
	cmd, err := trustedCmd(ctx, path, args...)
	if err != nil {
		return nil, err
	}
	return cmd.Output()
}
