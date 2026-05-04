//go:build !linux

package defs

func runCIS(o *Outcome, service string) {
	o.Check.Status = "fail"
	o.Check.Error = "cis probe is linux-only"
}
