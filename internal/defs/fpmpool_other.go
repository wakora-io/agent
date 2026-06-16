//go:build !linux

package defs

import "wakora.io/agent/internal/protocol"

func runFPMPool(o *Outcome, service string, p protocol.Probe) {
	o.Check.Status = "fail"
	o.Check.Error = "fpmpool probe is linux-only"
}
