//go:build linux

package agent

import (
	"log"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const mempinCap = 96 << 20

func PinOwnMappings() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	data, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		return
	}
	ranges := ownExeRanges(string(data), exe)
	if len(ranges) == 0 {
		return
	}
	unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY})
	var locked uint64
	var lockErr error
	for _, r := range ranges {
		size := r[1] - r[0]
		if locked+size > mempinCap {
			break
		}
		if _, _, errno := unix.Syscall(unix.SYS_MLOCK, uintptr(r[0]), uintptr(size), 0); errno == 0 {
			locked += size
		} else if lockErr == nil {
			lockErr = errno
		}
		unix.Syscall(unix.SYS_MADVISE, uintptr(r[0]), uintptr(size), uintptr(unix.MADV_RANDOM))
	}
	if lockErr != nil {
		log.Printf("own mappings pinned partially: %d MiB mlocked, mlock: %v (madvise random applied, refaults stay small)", locked>>20, lockErr)
		return
	}
	log.Printf("own mappings pinned: %d MiB mlocked - memory pressure cannot evict the agent text into disk re-reads", locked>>20)
}

func ownExeRanges(maps, exe string) [][2]uint64 {
	base := strings.TrimSuffix(exe, " (deleted)")
	var out [][2]uint64
	for _, line := range strings.Split(maps, "\n") {
		f := strings.Fields(line)
		if len(f) < 6 {
			continue
		}
		if !strings.Contains(f[1], "r") {
			continue
		}
		path := strings.TrimSuffix(strings.Join(f[5:], " "), " (deleted)")
		if path != base {
			continue
		}
		rng := strings.SplitN(f[0], "-", 2)
		if len(rng) != 2 {
			continue
		}
		start, err1 := strconv.ParseUint(rng[0], 16, 64)
		end, err2 := strconv.ParseUint(rng[1], 16, 64)
		if err1 != nil || err2 != nil || end <= start {
			continue
		}
		out = append(out, [2]uint64{start, end})
	}
	return out
}
