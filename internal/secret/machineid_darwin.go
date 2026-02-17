//go:build darwin

package secret

import (
	"os/exec"
	"regexp"
	"strings"
)

var platformUUIDRe = regexp.MustCompile(`"IOPlatformUUID"\s*=\s*"([^"]+)"`)

func platformMachineID() string {
	out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return ""
	}
	if m := platformUUIDRe.FindSubmatch(out); len(m) > 1 {
		return strings.TrimSpace(string(m[1]))
	}
	return ""
}
