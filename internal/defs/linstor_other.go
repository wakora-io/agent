//go:build !linux

package defs

import "wakora.io/agent/internal/protocol"

func runLinstor(o *Outcome, service string, p protocol.Probe, resolve CredResolver) {
	o.Check.Status = "fail"
	o.Check.Error = "linstor probing is linux only"
}
