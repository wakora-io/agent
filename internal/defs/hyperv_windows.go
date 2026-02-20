//go:build windows

package defs

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/yusufpapurcu/wmi"

	"wakora.io/agent/internal/protocol"
)

type msvmComputerSystem struct {
	Name                 string
	ElementName          string
	EnabledState         uint16
	OnTimeInMilliseconds *uint64
}

type msvmProcessorSettingData struct {
	InstanceID      string
	VirtualQuantity uint64
}

type msvmMemorySettingData struct {
	InstanceID      string
	VirtualQuantity uint64
}

const hypervNamespace = `root\virtualization\v2`

func runHyperV(o *Outcome, service string, p protocol.Probe) {
	o.Check.Target = "wmi:" + hypervNamespace

	var systems []msvmComputerSystem
	if err := wmi.QueryNamespace("SELECT Name, ElementName, EnabledState, OnTimeInMilliseconds FROM Msvm_ComputerSystem WHERE Caption = 'Virtual Machine'", &systems, hypervNamespace); err != nil {
		o.Check.Status = "fail"
		o.Check.Error = err.Error()
		return
	}
	var cpus []msvmProcessorSettingData
	_ = wmi.QueryNamespace("SELECT InstanceID, VirtualQuantity FROM Msvm_ProcessorSettingData", &cpus, hypervNamespace)
	var mems []msvmMemorySettingData
	_ = wmi.QueryNamespace("SELECT InstanceID, VirtualQuantity FROM Msvm_MemorySettingData", &mems, hypervNamespace)

	vcpuByGuid := map[string]uint64{}
	for _, c := range cpus {
		if g := hypervVMGuid(c.InstanceID); g != "" {
			vcpuByGuid[g] = c.VirtualQuantity
		}
	}
	memByGuid := map[string]uint64{}
	for _, m := range mems {
		if g := hypervVMGuid(m.InstanceID); g != "" {
			memByGuid[g] = m.VirtualQuantity
		}
	}

	o.Check.Status = "ok"
	prefix := "svc." + service + "."
	var total, running float64
	for _, s := range systems {
		if !looksLikeGuid(s.Name) {
			continue
		}
		total++
		guid := strings.ToLower(s.Name)
		state := hypervStateName(s.EnabledState)
		up := 0.0
		if s.EnabledState == 2 {
			up = 1
			running++
		}
		tags := map[string]string{"vm": s.ElementName}
		o.Metrics = append(o.Metrics,
			protocol.MetricPoint{Name: prefix + "guest.running", Value: up, Tags: tags},
			protocol.MetricPoint{Name: prefix + "guest.vcpus", Value: float64(vcpuByGuid[guid]), Tags: tags},
			protocol.MetricPoint{Name: prefix + "guest.mem_bytes", Value: float64(memByGuid[guid]) * 1024 * 1024, Tags: tags},
		)
		if s.EnabledState == 2 && s.OnTimeInMilliseconds != nil {
			o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: prefix + "guest.uptime_sec", Value: float64(*s.OnTimeInMilliseconds) / 1000, Tags: tags})
		}
		payload, _ := json.Marshal(map[string]string{"state": state, "hv": "hyperv", "vcpus": fmt.Sprint(vcpuByGuid[guid]), "memMB": fmt.Sprint(memByGuid[guid])})
		o.InvFacts = append(o.InvFacts, protocol.Fact{Kind: "guest", Key: s.ElementName, Payload: string(payload)})
	}
	o.Metrics = append(o.Metrics,
		protocol.MetricPoint{Name: prefix + "domains", Value: total},
		protocol.MetricPoint{Name: prefix + "running", Value: running},
	)
}
