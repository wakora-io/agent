package winsec

import "log"

func Protect(path string) {
	if err := ProtectDir(path); err != nil {
		log.Printf("cannot restrict %s to SYSTEM and Administrators: %v", path, err)
	}
}
