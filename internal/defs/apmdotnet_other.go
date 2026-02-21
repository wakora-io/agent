//go:build !linux

package defs

import "wakora.io/agent/internal/protocol"

func runAPMDotnet(o *Outcome, service string, p protocol.Probe, stateDir string) {
	o.Check.Status = "fail"
	o.Check.Error = "apmdotnet probe is linux/windows-only"
}
