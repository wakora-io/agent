//go:build !windows

package defs

import "os"

func openTail(path string) (*os.File, error) {
	return os.Open(path)
}
