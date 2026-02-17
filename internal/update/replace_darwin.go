//go:build darwin

package update

import (
	"os"
	"runtime"
)

// Darwin release assets are per-arch (wakora-darwin-amd64/arm64) so an Intel
// mac never pulls the arm64 build or the linux binary; missing asset 404s and
// the updater skips cleanly.
func assetNames() (bin, sum string) {
	base := "/wakora-darwin-" + runtime.GOARCH
	return base, base + ".sha256"
}

func replaceBinary(tmp, target string) error {
	return os.Rename(tmp, target)
}
