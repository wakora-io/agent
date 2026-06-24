//go:build linux

package doctor

import (
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func checkService() Check {
	unit := "wakora-agent"
	out, err := exec.Command("systemctl", "show", unit, "-p", "ActiveState", "-p", "SubState", "-p", "ActiveEnterTimestampMonotonic", "-p", "NRestarts").Output()
	if err == nil {
		kv := map[string]string{}
		for _, ln := range strings.Split(string(out), "\n") {
			if i := strings.IndexByte(ln, '='); i > 0 {
				kv[ln[:i]] = strings.TrimSpace(ln[i+1:])
			}
		}
		active := kv["ActiveState"]
		if active == "active" {
			detail := "running (systemd"
			if up := monotonicUptime(kv["ActiveEnterTimestampMonotonic"]); up != "" {
				detail += ", up " + up
			}
			if nr := kv["NRestarts"]; nr != "" && nr != "0" {
				detail += ", " + nr + " crash restarts"
			} else {
				detail += ", 0 crash restarts"
			}
			detail += ")"
			return Check{Name: "service", State: Ok, Detail: detail}
		}
		if active != "" {
			return Check{Name: "service", State: Warn, Detail: "systemd unit " + active + " (" + kv["SubState"] + ")",
				Next: "start it: systemctl start wakora-agent (or wakora service start)"}
		}
	}
	if running, _ := processRunning(); running {
		return Check{Name: "service", State: Ok, Detail: "running (process alive; not a systemd unit)"}
	}
	return Check{Name: "service", State: Warn, Detail: "not running as a managed service",
		Next: "install and start: wakora service install"}
}

func monotonicUptime(mono string) string {
	if mono == "" || mono == "0" {
		return ""
	}
	var usec int64
	for _, c := range mono {
		if c < '0' || c > '9' {
			return ""
		}
		usec = usec*10 + int64(c-'0')
	}
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return ""
	}
	nowUsec := ts.Sec*1_000_000 + int64(ts.Nsec)/1000
	d := time.Duration(nowUsec-usec) * time.Microsecond
	if d < 0 {
		return ""
	}
	days := int(d.Hours()) / 24
	h := int(d.Hours()) % 24
	m := int(d.Minutes()) % 60
	if days > 0 {
		return itoa(days) + "d " + itoa(h) + "h"
	}
	if h > 0 {
		return itoa(h) + "h " + itoa(m) + "m"
	}
	return itoa(m) + "m"
}

func processRunning() (bool, int) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false, 0
	}
	self := os.Getpid()
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid := atoiSafe(e.Name())
		if pid <= 0 || pid == self {
			continue
		}
		exe, err := os.Readlink("/proc/" + e.Name() + "/exe")
		if err != nil {
			continue
		}
		if strings.HasSuffix(exe, "/wakora") {
			return true, pid
		}
	}
	return false, 0
}

func freeBytes(dir string) int64 {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0
	}
	return int64(st.Bavail) * int64(st.Bsize)
}

func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return -1
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
