//go:build !windows

package update

import "os"

func assetNames() (bin, sum string) {
	return "/wakora", "/wakora.sha256"
}

func replaceBinary(tmp, target string) error {
	return os.Rename(tmp, target)
}
