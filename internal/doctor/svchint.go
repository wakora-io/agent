package doctor

import (
	"os"
	"runtime"
)

var hintGOOS = runtime.GOOS

var hintExists = func(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func serviceCmd(verb string) string {
	if hintGOOS != "linux" {
		return "wakora service " + verb
	}
	switch {
	case hintExists("/run/systemd/system"):
		return "systemctl " + verb + " wakora-agent"
	case hintExists("/run/openrc"):
		return "rc-service wakora-agent " + verb
	default:
		return "/etc/init.d/wakora-agent " + verb
	}
}
