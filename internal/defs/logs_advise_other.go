//go:build !linux

package defs

import "os"

func tailAdvise(_ *os.File) {}
