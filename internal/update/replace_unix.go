//go:build !windows && !darwin

package update

import (
	"os"
	"runtime"
)

func assetNames() (bin, sum string) {
	if runtime.GOARCH != "amd64" {
		base := "/wakora-linux-" + runtime.GOARCH
		return base, base + ".sha256"
	}
	return "/wakora", "/wakora.sha256"
}

func replaceBinary(tmp, target string) error {
	return os.Rename(tmp, target)
}
