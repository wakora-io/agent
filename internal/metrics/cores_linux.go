//go:build linux

package metrics

import (
	"runtime"

	"golang.org/x/sys/unix"
)

func coreCount() int {
	var set unix.CPUSet
	if err := unix.SchedGetaffinity(0, &set); err == nil {
		if n := set.Count(); n > 0 {
			return n
		}
	}
	return runtime.NumCPU()
}
