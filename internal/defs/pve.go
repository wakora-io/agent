package defs

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"wakora.io/agent/internal/protocol"
)

type pveResource struct {
	Type    string  `json:"type"`
	VMID    float64 `json:"vmid"`
	Name    string  `json:"name"`
	Node    string  `json:"node"`
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

type pveStatusRow struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Local   int    `json:"local"`
	Online  int    `json:"online"`
	Quorate int    `json:"quorate"`
	Nodes   int    `json:"nodes"`
	NodeID  int    `json:"nodeid"`
}

type pveHARow struct {
	Type  string `json:"type"`
	SID   string `json:"sid"`
	State string `json:"state"`
	Node  string `json:"node"`
}

type pveTaskRow struct {
	UPID      string  `json:"upid"`
	Node      string  `json:"node"`
	Type      string  `json:"type"`
	Status    string  `json:"status"`
	StartTime float64 `json:"starttime"`
	EndTime   float64 `json:"endtime"`
	User      string  `json:"user"`
	ID        string  `json:"id"`
}

var pveTaskKinds = map[string]string{
	"qmigrate": "migration", "vzmigrate": "migration", "migrate": "migration",
	"hamigrate": "migration", "vzdump": "backup",
}

type pveMem struct {
	localNode string
	seen      map[string]bool
	seeded    bool
	failed    map[string]bool
	clustered bool
}

var pveState = &pveMem{seen: map[string]bool{}, failed: map[string]bool{}}

func pveGet(path, api string, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "get", api, "--output-format", "json")
	cmd.Env = execEnv()
	out, err := cmd.Output()
	return out, execErrText(err)
}

func runPVE(o *Outcome, service string, p protocol.Probe, timeout time.Duration) {
	o.Check.Target = "pvesh /cluster/resources"
	path, err := exec.LookPath("pvesh")
	if err != nil {
		o.Check.Status = "fail"
		o.Check.Error = err.Error()
		return
	}
	out, err := pveGet(path, "/cluster/resources", timeout)
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

	var cluster *pveStatusRow
	var nodeRows []pveStatusRow
	if statusOut, err := pveGet(path, "/cluster/status", timeout); err == nil {
		var rows []pveStatusRow
		if json.Unmarshal(statusOut, &rows) == nil {
			for i, r := range rows {
				switch r.Type {
				case "cluster":
					cluster = &rows[i]
				case "node":
					nodeRows = append(nodeRows, r)
					if r.Local == 1 && r.Name != "" {
						pveState.localNode = r.Name
					}
				}
			}
		}
	}

	pveEmit(o, service, resources, pveState.localNode)
	if cluster != nil {
		pveState.clustered = true
		pveEmitCluster(o, service, cluster, nodeRows)
		pveHA(o, service, path)
	}
	if pveState.clustered || pveClusterConf() {
		pveState.clustered = true
		pveEmitCorosync(o, service)
	}
	pveTasks(o, service, path)
}

func pveClusterConf() bool {
	_, err := os.Stat("/etc/pve/corosync.conf")
	return err == nil
}

func pveEmitCorosync(o *Outcome, service string) {
	up, _, ok := unitState("corosync.service")
	if !ok {
		return
	}
	o.Metrics = append(o.Metrics, protocol.MetricPoint{
		Name: "svc." + service + ".cluster.corosync_active", Value: up,
	})
}

func pveEmit(o *Outcome, service string, resources []pveResource, localNode string) {
	prefix := "svc." + service + "."
	var vms, vmsRun, cts, ctsRun float64
	for _, r := range resources {
		if localNode != "" && r.Node != "" && r.Node != localNode {
			continue
		}
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

func pveEmitCluster(o *Outcome, service string, cluster *pveStatusRow, nodes []pveStatusRow) {
	prefix := "svc." + service + ".cluster."
	online := 0.0
	for _, n := range nodes {
		v := 0.0
		if n.Online == 1 {
			v = 1
			online++
		}
		o.Metrics = append(o.Metrics, protocol.MetricPoint{
			Name: prefix + "node.online", Value: v, Tags: map[string]string{"node": n.Name},
		})
		if n.NodeID > 0 {
			o.Metrics = append(o.Metrics, protocol.MetricPoint{
				Name: prefix + "node.id", Value: float64(n.NodeID), Tags: map[string]string{"node": n.Name},
			})
		}
	}
	total := float64(cluster.Nodes)
	if total == 0 {
		total = float64(len(nodes))
	}
	o.Metrics = append(o.Metrics,
		protocol.MetricPoint{Name: prefix + "quorate", Value: float64(cluster.Quorate)},
		protocol.MetricPoint{Name: prefix + "nodes", Value: total},
		protocol.MetricPoint{Name: prefix + "nodes_online", Value: online},
	)
}

func pveHA(o *Outcome, service, path string) {
	out, err := pveGet(path, "/cluster/ha/status", 10*time.Second)
	if err != nil {
		return
	}
	var rows []pveHARow
	if json.Unmarshal(out, &rows) != nil {
		return
	}
	pveHAEmit(o, service, rows)
}

func pveHAEmit(o *Outcome, service string, rows []pveHARow) {
	var res, errs float64
	emitted := 0
	for _, r := range rows {
		if r.Type == "master" && r.Node != "" {
			o.Metrics = append(o.Metrics, protocol.MetricPoint{
				Name: "svc." + service + ".ha.master", Value: 1, Tags: map[string]string{"node": r.Node},
			})
			continue
		}
		if r.Type != "service" || r.SID == "" {
			continue
		}
		res++
		bad := 0.0
		if r.State == "error" || r.State == "fence" {
			bad = 1
			errs++
		}
		if emitted < 50 {
			o.Metrics = append(o.Metrics, protocol.MetricPoint{
				Name: "svc." + service + ".ha.resource.error", Value: bad, Tags: map[string]string{"sid": r.SID},
			})
			emitted++
		}
	}
	if res > 0 {
		o.Metrics = append(o.Metrics,
			protocol.MetricPoint{Name: "svc." + service + ".ha.resources", Value: res},
			protocol.MetricPoint{Name: "svc." + service + ".ha.errors", Value: errs},
		)
	}
}

func pveTasks(o *Outcome, service, path string) {
	out, err := pveGet(path, "/cluster/tasks", 10*time.Second)
	if err != nil {
		return
	}
	var rows []pveTaskRow
	if json.Unmarshal(out, &rows) != nil {
		return
	}
	pveTasksEmit(o, rows, func(node, upid string) []byte {
		raw, lerr := pveGet(path, "/nodes/"+node+"/tasks/"+upid+"/log", 8*time.Second)
		if lerr != nil {
			return nil
		}
		return raw
	})
}

var pveMigTargetRe = regexp.MustCompile(`to node '([^']+)'`)

func pveTaskTarget(raw []byte) string {
	var lines []struct {
		T string `json:"t"`
	}
	if raw == nil || json.Unmarshal(raw, &lines) != nil {
		return ""
	}
	for i, l := range lines {
		if i >= 25 {
			break
		}
		if m := pveMigTargetRe.FindStringSubmatch(l.T); m != nil {
			return m[1]
		}
	}
	return ""
}

func pveTasksEmit(o *Outcome, rows []pveTaskRow, logFn func(node, upid string) []byte) {
	if !pveState.seeded {
		for _, r := range rows {
			if r.UPID != "" {
				pveState.seen[r.UPID] = true
			}
		}
		pveState.seeded = true
		return
	}
	if len(pveState.seen) > 5000 {
		fresh := map[string]bool{}
		for _, r := range rows {
			if r.UPID != "" {
				fresh[r.UPID] = true
			}
		}
		pveState.seen = fresh
	}
	emitted := 0
	logsRead := 0
	for _, r := range rows {
		if r.UPID == "" || r.EndTime <= 0 || pveState.seen[r.UPID] {
			continue
		}
		pveState.seen[r.UPID] = true
		task, known := pveTaskKinds[r.Type]
		failed := r.Status != "" && r.Status != "OK"
		if pveState.failed == nil {
			pveState.failed = map[string]bool{}
		}
		key := r.Type + "/" + r.ID
		recovered := false
		if failed {
			if len(pveState.failed) < 500 {
				pveState.failed[key] = true
			}
		} else if pveState.failed[key] {
			recovered = true
			delete(pveState.failed, key)
		}
		if (!known && !failed && !recovered) || emitted >= 20 {
			continue
		}
		if !known {
			task = "task"
		}
		status := r.Status
		if len(status) > 200 {
			status = status[:200]
		}
		det := map[string]any{
			"task": task, "type": r.Type, "node": r.Node, "guest": r.ID,
			"status": status, "durationSec": int(r.EndTime - r.StartTime), "user": r.User,
		}
		if task == "migration" && logFn != nil && logsRead < 4 {
			logsRead++
			if t := pveTaskTarget(logFn(r.Node, r.UPID)); t != "" {
				det["target"] = t
			}
		}
		detail, err := json.Marshal(det)
		if err != nil {
			continue
		}
		o.Events = append(o.Events, protocol.AgentEvent{
			Kind: "pve_task", Detail: string(detail), Timestamp: int64(r.EndTime),
		})
		emitted++
	}
}
