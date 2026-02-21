package defs

import (
	"time"

	"wakora.io/agent/internal/protocol"
)

func RunAPMProfile(service string, p protocol.Probe) Outcome {
	o := Outcome{Check: protocol.CheckResult{
		CheckID:   service + "/" + p.Name,
		Kind:      p.Type,
		Timestamp: time.Now().Unix(),
	}}
	start := time.Now()
	runAPMProfile(&o, service, p)
	o.Check.LatencyMs = float64(time.Since(start).Microseconds()) / 1000
	return o
}
