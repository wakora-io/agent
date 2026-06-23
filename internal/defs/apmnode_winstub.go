//go:build !windows

package defs

import "wakora.io/agent/internal/protocol"

func runAPMNodeWindows(o *Outcome, service string, p protocol.Probe, stateDir string) {}
