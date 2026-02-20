//go:build darwin

package update

import (
	"os"
	"runtime"
)

func assetNames() (bin, sum string) {
	base := "/wakora-darwin-" + runtime.GOARCH
	return base, base + ".sha256"
}

func replaceBinary(tmp, target string) error {
	return os.Rename(tmp, target)
}
