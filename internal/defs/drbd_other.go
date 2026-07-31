//go:build !linux

package defs

import "time"

func runDRBD(o *Outcome, service string, timeout time.Duration) {
	o.Check.Status = "fail"
	o.Check.Error = "drbd probing is linux only"
}
