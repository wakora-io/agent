//go:build !linux

package defs

import "wakora.io/agent/internal/protocol"

func runAPMPhp(o *Outcome, service string, p protocol.Probe, stateDir string) {
	o.Check.Status = "fail"
	o.Check.Error = "apmphp probe is linux-only"
}
