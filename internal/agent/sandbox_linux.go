//go:build linux

package agent

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"wakora.io/agent/internal/atomicfile"
)

var sandboxExecPaths = []string{"/var/log", "/tmp", "/var/tmp", "/var/lib"}

const (
	sandboxRelaxWindow = 6 * time.Hour
	sandboxDropIn      = "50-wakora-sandbox.conf"
	sandboxMarker      = "/run/wakora-sandbox-relax"
)

func EnsureSandboxHeadroom() bool {
	blocked := sandboxRestricted(sandboxExecPaths, pathReadOnly)
	if len(blocked) == 0 {
		return false
	}
	unit, _, ok := selfServiceCgroup()
	if !ok {
		return false
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	if relaxRecent(sandboxMarker, time.Now(), sandboxRelaxWindow) {
		log.Printf("sandbox: %s still mounts %s read-only for exec children after a relax attempt; not retrying (probes that need a writable path, such as a web server config dump, will keep failing until the unit file is updated)",
			unit, strings.Join(blocked, " "))
		return false
	}
	dir := filepath.Join("/run/systemd/system", unit+".d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Printf("sandbox: cannot stage a runtime drop-in for %s: %v", unit, err)
		return false
	}
	body := "[Service]\nProtectSystem=full\n"
	if err := atomicfile.Write(filepath.Join(dir, sandboxDropIn), []byte(body), 0o644); err != nil {
		log.Printf("sandbox: cannot write the runtime drop-in for %s: %v", unit, err)
		return false
	}
	_ = atomicfile.Write(sandboxMarker, []byte(strconv.FormatInt(time.Now().Unix(), 10)), 0o600)
	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		log.Printf("sandbox: daemon-reload failed after staging the drop-in for %s: %v (%s)", unit, err, strings.TrimSpace(string(out)))
		return false
	}
	log.Printf("sandbox: %s mounted %s read-only for our exec children, so a config dump or a temp file of the monitored service failed with a read-only filesystem even though the host itself is writable; staged a runtime drop-in with ProtectSystem=full (system binaries and /etc stay read-only) and restarting to rebuild the mount namespace",
		unit, strings.Join(blocked, " "))
	return true
}

func sandboxRestricted(paths []string, check func(string) (bool, bool)) []string {
	var blocked []string
	for _, p := range paths {
		ro, ok := check(p)
		if ok && ro {
			blocked = append(blocked, p)
		}
	}
	return blocked
}

func pathReadOnly(p string) (bool, bool) {
	var st unix.Statfs_t
	if err := unix.Statfs(p, &st); err != nil {
		return false, false
	}
	return st.Flags&unix.ST_RDONLY != 0, true
}

func relaxRecent(marker string, now time.Time, window time.Duration) bool {
	raw, err := os.ReadFile(marker)
	if err != nil {
		return false
	}
	sec, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return false
	}
	return now.Sub(time.Unix(sec, 0)) < window
}
