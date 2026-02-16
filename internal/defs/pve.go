package defs

import (
	"context"
	"encoding/json"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"wakora.io/agent/internal/protocol"
)

type pveResource struct {
	Type    string  `json:"type"`
	VMID    float64 `json:"vmid"`
	Name    string  `json:"name"`
	Status  string  `json:"status"`
	CPU     float64 `json:"cpu"`
	MaxCPU  float64 `json:"maxcpu"`
	Mem     float64 `json:"mem"`
	MaxMem  float64 `json:"maxmem"`
	Disk    float64 `json:"disk"`
	MaxDisk float64 `json:"maxdisk"`
	Uptime  float64 `json:"uptime"`
	Storage string  `json:"storage"`
}

func runPVE(o *Outcome, service string, p protocol.Probe, timeout time.Duration) {
	o.Check.Target = "pvesh /cluster/resources"
	path, err := exec.LookPath("pvesh")
	if err != nil {
		o.Check.Status = "fail"
		o.Check.Error = err.Error()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "get", "/cluster/resources", "--output-format", "json").Output()
	if err != nil {
		o.Check.Status = "fail"
		o.Check.Error = strings.TrimSpace(err.Error())
		return
	}
	var resources []pveResource
	if err := json.Unmarshal(out, &resources); err != nil {
		o.Check.Status = "fail"
		o.Check.Error = "pvesh json: " + err.Error()
		return
	}
	o.Check.Status = "ok"
	pveEmit(o, service, resources)
}

func pveEmit(o *Outcome, service string, resources []pveResource) {
	prefix := "svc." + service + "."
	var vms, vmsRun, cts, ctsRun float64
	for _, r := range resources {
		switch r.Type {
		case "qemu", "lxc":
			running := 0.0
			if r.Status == "running" {
				running = 1
			}
			if r.Type == "qemu" {
				vms++
				vmsRun += running
			} else {
				cts++
				ctsRun += running
			}
			tags := map[string]string{
				"vmid": strconv.Itoa(int(r.VMID)),
				"name": r.Name,
				"type": r.Type,
			}
			o.Metrics = append(o.Metrics,
				protocol.MetricPoint{Name: prefix + "guest.running", Value: running, Tags: tags},
			)
			if running == 1 {
				o.Metrics = append(o.Metrics,
					protocol.MetricPoint{Name: prefix + "guest.cpu_pct", Value: r.CPU * 100, Tags: tags},
					protocol.MetricPoint{Name: prefix + "guest.mem_bytes", Value: r.Mem, Tags: tags},
					protocol.MetricPoint{Name: prefix + "guest.uptime", Value: r.Uptime, Tags: tags},
				)
				if r.MaxMem > 0 {
					o.Metrics = append(o.Metrics,
						protocol.MetricPoint{Name: prefix + "guest.mem_pct", Value: r.Mem / r.MaxMem * 100, Tags: tags})
				}
				if r.MaxDisk > 0 && r.Disk > 0 {
					o.Metrics = append(o.Metrics,
						protocol.MetricPoint{Name: prefix + "guest.disk_pct", Value: r.Disk / r.MaxDisk * 100, Tags: tags})
				}
			}
			payload, err := json.Marshal(map[string]string{"name": r.Name, "type": r.Type, "status": r.Status})
			if err == nil {
				o.InvFacts = append(o.InvFacts, protocol.Fact{
					Kind: "guest", Key: strconv.Itoa(int(r.VMID)), Payload: string(payload),
				})
			}
		case "storage":
			if r.MaxDisk > 0 {
				o.Metrics = append(o.Metrics, protocol.MetricPoint{
					Name: prefix + "storage.used_pct", Value: r.Disk / r.MaxDisk * 100,
					Tags: map[string]string{"storage": r.Storage},
				})
			}
		}
	}
	o.Metrics = append(o.Metrics,
		protocol.MetricPoint{Name: prefix + "vms", Value: vms},
		protocol.MetricPoint{Name: prefix + "vms_running", Value: vmsRun},
		protocol.MetricPoint{Name: prefix + "cts", Value: cts},
		protocol.MetricPoint{Name: prefix + "cts_running", Value: ctsRun},
	)
}
