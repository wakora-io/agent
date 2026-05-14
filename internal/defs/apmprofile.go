package defs

import (
	"sort"
	"time"

	"wakora.io/agent/internal/protocol"
)

func RunAPMProfile(service string, p protocol.Probe) (o Outcome) {
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
	runAPMProfile(&o, service, p)
	o.Check.LatencyMs = float64(time.Since(start).Microseconds()) / 1000
	return o
}

func topStacks(folded map[string]uint32, max int) []protocol.FoldedStack {
	stacks := make([]protocol.FoldedStack, 0, len(folded))
	for k, v := range folded {
		stacks = append(stacks, protocol.FoldedStack{Stack: k, Samples: v})
	}
	sort.Slice(stacks, func(i, j int) bool { return stacks[i].Samples > stacks[j].Samples })
	if len(stacks) > max {
		stacks = stacks[:max]
	}
	return stacks
}
