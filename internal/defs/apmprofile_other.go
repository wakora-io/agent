//go:build !linux

package defs

import "wakora.io/agent/internal/protocol"

func runAPMProfile(o *Outcome, service string, p protocol.Probe) {
	o.Check.Status = "fail"
	o.Check.Error = "apmprofile probe is linux-only"
}
