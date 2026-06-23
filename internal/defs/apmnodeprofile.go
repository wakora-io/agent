package defs

import (
	"time"

	"wakora.io/agent/internal/protocol"
)

func RunAPMNodeProfile(service string, p protocol.Probe) (o Outcome) {
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
	runAPMNodeProfile(&o, service, p)
	o.Check.LatencyMs = float64(time.Since(start).Microseconds()) / 1000
	return o
}
