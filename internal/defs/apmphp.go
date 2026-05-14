package defs

import (
	"sync/atomic"
	"time"

	"wakora.io/agent/internal/protocol"
)

var stagingDenied atomic.Bool

func SetStagingDenied(v bool) { stagingDenied.Store(v) }

var deepTraceAllowed atomic.Bool

func SetDeepTraceAllowed(v bool) { deepTraceAllowed.Store(v) }

func RunAPMPhp(service string, p protocol.Probe, stateDir string) (o Outcome) {
	o = Outcome{Check: protocol.CheckResult{
		CheckID:   service + "/" + p.Name,
		Kind:      p.Type,
		Timestamp: time.Now().Unix(),
	}}
	defer func() {
		if r := recover(); r != nil {
			recoverProbe(&o, r)
		}
	}()
	start := time.Now()
	runAPMPhp(&o, service, p, stateDir)
	o.Check.LatencyMs = float64(time.Since(start).Microseconds()) / 1000
	return o
}
