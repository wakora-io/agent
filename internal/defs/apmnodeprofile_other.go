//go:build !linux

package defs

import "wakora.io/agent/internal/protocol"

func runAPMNodeProfile(o *Outcome, service string, p protocol.Probe) {
	o.Check.Status = "fail"
	o.Check.Error = "apmnodeprofile probe is linux-only"
}
