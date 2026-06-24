//go:build darwin

package doctor

import (
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"
)

func checkService() Check {
	out, err := exec.Command("launchctl", "list").Output()
	if err == nil && strings.Contains(string(out), "io.wakora.agent") {
		return Check{Name: "service", State: Ok, Detail: "running (launchd)"}
	}
	return Check{Name: "service", State: Warn, Detail: "not loaded in launchd",
		Next: "install and start: wakora service install"}
}

func freeBytes(dir string) int64 {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0
	}
	return int64(st.Bavail) * int64(st.Bsize)
}
