//go:build !windows

package defs

import "wakora.io/agent/internal/protocol"

func runHyperV(o *Outcome, service string, p protocol.Probe) {
	o.Check.Status = "fail"
	o.Check.Error = "hyperv probe is windows-only"
}
