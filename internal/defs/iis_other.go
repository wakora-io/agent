//go:build !windows

package defs

import (
	"time"

	"wakora.io/agent/internal/protocol"
)

func runIIS(o *Outcome, service string, p protocol.Probe, timeout time.Duration) {
	o.Check.Status = "fail"
	o.Check.Error = "iis probe is windows-only"
}
