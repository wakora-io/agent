//go:build linux

package defs

import (
	"os"

	"golang.org/x/sys/unix"
)

func tailAdvise(f *os.File) {
	_ = unix.Fadvise(int(f.Fd()), 0, 0, unix.FADV_RANDOM)
}
