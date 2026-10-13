//go:build !linux

package agent

import "net"

func loopbackPeerUID(server, client *net.TCPAddr) (uint32, bool) { return 0, false }

func scanOTLPSenders() map[uint32]bool { return map[uint32]bool{0: true} }
