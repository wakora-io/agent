//go:build linux

package metrics

import (
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCoreCountFollowsAffinity(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var set unix.CPUSet
	if err := unix.SchedGetaffinity(0, &set); err != nil {
		t.Skip(err)
	}
	if got, want := coreCount(), set.Count(); got != want {
		t.Fatalf("coreCount %d, affinity %d", got, want)
	}
	var one unix.CPUSet
	for i := 0; i < 1024; i++ {
		if set.IsSet(i) {
			one.Set(i)
			break
		}
	}
	if err := unix.SchedSetaffinity(0, &one); err != nil {
		t.Skip(err)
	}
	defer unix.SchedSetaffinity(0, &set)
	if got := coreCount(); got != 1 {
		t.Fatalf("after narrowing affinity to one cpu coreCount read %d", got)
	}
}
