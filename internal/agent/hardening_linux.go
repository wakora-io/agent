//go:build linux

package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"wakora.io/agent/internal/atomicfile"
)

const (
	hardeningDropIn     = "40-wakora-hardening.conf"
	hardeningUnitRoot   = "/etc/systemd/system"
	hardeningMinSystemd = 232
)

var hardeningPaths = []string{"/etc/wakora", "/var/lib/wakora", "/var/log/wakora", "/usr/local/bin"}

func EnsureUnitHardening(stateDir string) bool {
	unit, _, ok := selfServiceCgroup()
	if !ok {
		return false
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	out, err := exec.Command("systemctl", "show", "-p", "ProtectSystem", "--value", unit).Output()
	if err != nil || !unitUnhardened(strings.TrimSpace(string(out))) {
		return false
	}
	ver, err := exec.Command("systemctl", "--version").Output()
	if err != nil || systemdVersion(string(ver)) < hardeningMinSystemd {
		log.Printf("unit hardening: %s runs without ProtectSystem, but this systemd is too old for the hardening drop-in (needs %d); leaving the unit as installed", unit, hardeningMinSystemd)
		return false
	}
	exe, _ := os.Executable()
	body := hardeningBody(filepath.Dir(exe))
	sum := sha256.Sum256([]byte(body))
	stamp := hex.EncodeToString(sum[:])
	marker := filepath.Join(stateDir, "unit-hardening")
	if prev, err := os.ReadFile(marker); err == nil && strings.TrimSpace(string(prev)) == stamp {
		log.Printf("unit hardening: %s still runs without ProtectSystem after %s was installed; not retrying", unit, hardeningDropIn)
		return false
	}
	dir := filepath.Join(hardeningUnitRoot, unit+".d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Printf("unit hardening: cannot create %s: %v", dir, err)
		return false
	}
	if err := atomicfile.Write(filepath.Join(dir, hardeningDropIn), []byte(body), 0o644); err != nil {
		log.Printf("unit hardening: cannot write the drop-in for %s: %v", unit, err)
		return false
	}
	_ = atomicfile.Write(marker, []byte(stamp), 0o600)
	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		log.Printf("unit hardening: daemon-reload failed after writing the drop-in for %s: %v (%s)", unit, err, strings.TrimSpace(string(out)))
		return false
	}
	log.Printf("unit hardening: %s was installed before the service hardening shipped; added %s (system directories read-only apart from the agent's own, home directories read-only, control groups protected, no memory limit) and restarting once to apply it", unit, hardeningDropIn)
	return true
}

func unitUnhardened(protectSystem string) bool {
	return protectSystem == "no"
}

func systemdVersion(out string) int {
	f := strings.Fields(out)
	if len(f) < 2 || f[0] != "systemd" {
		return 0
	}
	n, err := strconv.Atoi(f[1])
	if err != nil {
		return 0
	}
	return n
}

func hardeningBody(binDir string) string {
	paths := append([]string{}, hardeningPaths...)
	if binDir != "" && binDir != "." && !containsString(paths, binDir) {
		paths = append(paths, binDir)
	}
	for i, p := range paths {
		paths[i] = "-" + p
	}
	return "[Service]\n" +
		"ProtectSystem=full\n" +
		"ProtectHome=read-only\n" +
		"ProtectControlGroups=yes\n" +
		"ReadWritePaths=" + strings.Join(paths, " ") + "\n"
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
