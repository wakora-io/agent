//go:build !linux

package metrics

import "runtime"

func coreCount() int {
	return runtime.NumCPU()
}
