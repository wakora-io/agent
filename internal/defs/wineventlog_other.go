//go:build !windows

package defs

import "wakora.io/agent/internal/protocol"

func runEventLog(o *Outcome, service string, p protocol.Probe) {
	o.Check.Status = "fail"
	o.Check.Error = "wineventlog probe is windows-only"
}
