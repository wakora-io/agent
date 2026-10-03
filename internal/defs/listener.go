package defs

import (
	"log"
	"runtime/debug"
)

func recoverListener(kind string, port int) {
	if r := recover(); r != nil {
		log.Printf("%s listener on udp/%d dropped a packet that panicked the parser: %v\n%s", kind, port, r, debug.Stack())
	}
}
