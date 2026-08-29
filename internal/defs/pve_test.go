package defs

import (
	"encoding/json"
	"testing"
)

func TestPVEEmit(t *testing.T) {
	raw := `[
		{"type":"node","node":"pve-1","status":"online","cpu":0.05,"maxcpu":32},
		{"type":"qemu","vmid":100,"name":"win-test","status":"running","cpu":0.121,"maxcpu":4,"mem":2147483648,"maxmem":4294967296,"disk":0,"maxdisk":34359738368,"uptime":3600},
		{"type":"qemu","vmid":101,"name":"vm-off","status":"stopped","cpu":0,"maxcpu":2,"mem":0,"maxmem":1073741824},
		{"type":"lxc","vmid":1082,"name":"web-1","status":"running","cpu":0.004,"maxcpu":2,"mem":104857600,"maxmem":1073741824,"disk":1073741824,"maxdisk":8589934592,"uptime":86400},
		{"type":"storage","storage":"local","status":"available","disk":50,"maxdisk":100},
		{"type":"storage","storage":"backup","status":"available","disk":0,"maxdisk":0}
	]`
	var resources []pveResource
	if err := json.Unmarshal([]byte(raw), &resources); err != nil {
		t.Fatal(err)
	}
	var o Outcome
	pveEmit(&o, "proxmox", resources, "")

	byName := map[string][]float64{}
	tagsSeen := map[string]string{}
	for _, m := range o.Metrics {
		byName[m.Name] = append(byName[m.Name], m.Value)
		if m.Tags != nil {
			tagsSeen[m.Name+"/"+m.Tags["vmid"]+m.Tags["storage"]] = m.Tags["name"] + m.Tags["type"] + m.Tags["storage"]
		}
	}

	if v := byName["svc.proxmox.vms"]; len(v) != 1 || v[0] != 2 {
		t.Fatalf("vms = %v, want [2]", v)
	}
	if v := byName["svc.proxmox.vms_running"]; v[0] != 1 {
		t.Fatalf("vms_running = %v, want 1", v)
	}
	if v := byName["svc.proxmox.cts"]; v[0] != 1 || byName["svc.proxmox.cts_running"][0] != 1 {
		t.Fatal("ct counts wrong")
	}

	if v := byName["svc.proxmox.guest.cpu_pct"]; len(v) != 2 {
		t.Fatalf("cpu_pct only for running guests, got %d values", len(v))
	}
	if tagsSeen["svc.proxmox.guest.cpu_pct/100"] != "win-testqemu" {
		t.Fatalf("qemu guest tags wrong: %q", tagsSeen["svc.proxmox.guest.cpu_pct/100"])
	}

	memPct := byName["svc.proxmox.guest.mem_pct"]
	if len(memPct) != 2 || memPct[0] != 50 {
		t.Fatalf("mem_pct = %v, want first 50", memPct)
	}
	if v := byName["svc.proxmox.guest.disk_pct"]; len(v) != 1 || v[0] != 12.5 {
		t.Fatalf("disk_pct = %v, want [12.5] (lxc only, qemu disk=0 skipped)", v)
	}
	if v := byName["svc.proxmox.guest.running"]; len(v) != 3 {
		t.Fatalf("running metric must cover all guests incl stopped, got %d", len(v))
	}

	if v := byName["svc.proxmox.storage.used_pct"]; len(v) != 1 || v[0] != 50 {
		t.Fatalf("storage.used_pct = %v, want [50] (zero-maxdisk skipped)", v)
	}

	if len(o.InvFacts) != 3 {
		t.Fatalf("want 3 guest facts, got %d", len(o.InvFacts))
	}
	if o.InvFacts[2].Kind != "guest" || o.InvFacts[2].Key != "1082" {
		t.Fatalf("guest fact wrong: %+v", o.InvFacts[2])
	}
}

func TestPVEEmitClusterFiltersToLocalNode(t *testing.T) {
	raw := `[
		{"type":"lxc","vmid":100,"name":"mine","node":"node-a","status":"running","cpu":0.1,"mem":1,"maxmem":2},
		{"type":"lxc","vmid":101,"name":"foreign","node":"node-b","status":"running","cpu":0.1,"mem":1,"maxmem":2},
		{"type":"qemu","vmid":102,"name":"foreign-vm","node":"node-c","status":"stopped"},
		{"type":"storage","storage":"local","node":"node-a","disk":10,"maxdisk":100},
		{"type":"storage","storage":"local","node":"node-b","disk":90,"maxdisk":100}
	]`
	var resources []pveResource
	if err := json.Unmarshal([]byte(raw), &resources); err != nil {
		t.Fatal(err)
	}
	var o Outcome
	pveEmit(&o, "proxmox", resources, "node-a")

	counts := map[string]float64{}
	storages := 0
	var storageVal float64
	for _, m := range o.Metrics {
		counts[m.Name] = m.Value
		if m.Name == "svc.proxmox.storage.used_pct" {
			storages++
			storageVal = m.Value
		}
	}
	if counts["svc.proxmox.cts"] != 1 || counts["svc.proxmox.vms"] != 0 {
		t.Fatalf("counts must be local-only: cts=%v vms=%v", counts["svc.proxmox.cts"], counts["svc.proxmox.vms"])
	}
	if storages != 1 || storageVal != 10 {
		t.Fatalf("storage must keep only the local node row: n=%d v=%v", storages, storageVal)
	}
	if len(o.InvFacts) != 1 || o.InvFacts[0].Key != "100" {
		t.Fatalf("guest inventory must be local-only: %+v", o.InvFacts)
	}
}

func TestPVEEmitSingleNodeUnchanged(t *testing.T) {
	raw := `[
		{"type":"lxc","vmid":200,"name":"ct","node":"pve-1","status":"running","cpu":0.1,"mem":1,"maxmem":2},
		{"type":"storage","storage":"local-lvm","node":"pve-1","disk":50,"maxdisk":100}
	]`
	var resources []pveResource
	if err := json.Unmarshal([]byte(raw), &resources); err != nil {
		t.Fatal(err)
	}
	var filtered, plain Outcome
	pveEmit(&filtered, "proxmox", resources, "pve-1")
	pveEmit(&plain, "proxmox", resources, "")
	if len(filtered.Metrics) != len(plain.Metrics) || len(filtered.InvFacts) != len(plain.InvFacts) {
		t.Fatal("local filter on a single-node host must be a no-op")
	}
}

func TestPVEEmitClusterMetrics(t *testing.T) {
	cluster := &pveStatusRow{Type: "cluster", Name: "prod", Quorate: 1, Nodes: 3}
	nodes := []pveStatusRow{
		{Type: "node", Name: "node-a", Local: 1, Online: 1, NodeID: 1},
		{Type: "node", Name: "node-b", Online: 1, NodeID: 2},
		{Type: "node", Name: "node-c", Online: 0, NodeID: 3},
	}
	var o Outcome
	pveEmitCluster(&o, "proxmox", cluster, nodes)
	vals := map[string]float64{}
	perNode := map[string]float64{}
	ids := map[string]float64{}
	for _, m := range o.Metrics {
		if m.Name == "svc.proxmox.cluster.node.online" {
			perNode[m.Tags["node"]] = m.Value
			continue
		}
		if m.Name == "svc.proxmox.cluster.node.id" {
			ids[m.Tags["node"]] = m.Value
			continue
		}
		vals[m.Name] = m.Value
	}
	if vals["svc.proxmox.cluster.quorate"] != 1 || vals["svc.proxmox.cluster.nodes"] != 3 || vals["svc.proxmox.cluster.nodes_online"] != 2 {
		t.Fatalf("cluster metrics wrong: %+v", vals)
	}
	if perNode["node-c"] != 0 || perNode["node-a"] != 1 {
		t.Fatalf("per-node online wrong: %+v", perNode)
	}
	if ids["node-a"] != 1 || ids["node-c"] != 3 {
		t.Fatalf("node ids wrong: %+v", ids)
	}
}

func TestPVEHAEmit(t *testing.T) {
	rows := []pveHARow{
		{Type: "quorum"},
		{Type: "master", Node: "node-b"},
		{Type: "lrm"},
		{Type: "service", SID: "ct:100", State: "started"},
		{Type: "service", SID: "ct:101", State: "error"},
	}
	var o Outcome
	pveHAEmit(&o, "proxmox", rows)
	vals := map[string]float64{}
	errBySid := map[string]float64{}
	master := ""
	for _, m := range o.Metrics {
		if m.Name == "svc.proxmox.ha.resource.error" {
			errBySid[m.Tags["sid"]] = m.Value
			continue
		}
		if m.Name == "svc.proxmox.ha.master" {
			master = m.Tags["node"]
			continue
		}
		vals[m.Name] = m.Value
	}
	if vals["svc.proxmox.ha.resources"] != 2 || vals["svc.proxmox.ha.errors"] != 1 {
		t.Fatalf("ha totals wrong: %+v", vals)
	}
	if errBySid["ct:101"] != 1 || errBySid["ct:100"] != 0 {
		t.Fatalf("per-sid error wrong: %+v", errBySid)
	}
	if master != "node-b" {
		t.Fatalf("ha master node = %q, want node-b", master)
	}
}

func TestPVETaskRecoveryEmitsOncePerTypeGuest(t *testing.T) {
	pveState = &pveMem{seen: map[string]bool{}, failed: map[string]bool{}, seeded: true}
	var o1 Outcome
	pveTasksEmit(&o1, []pveTaskRow{
		{UPID: "f1", Type: "vzdelsnapshot", Status: "storage is busy", StartTime: 100, EndTime: 110, Node: "node-c", ID: "111"},
	}, nil)
	if len(o1.Events) != 1 {
		t.Fatalf("a failed task of an unknown type must emit, got %d", len(o1.Events))
	}
	var o2 Outcome
	pveTasksEmit(&o2, []pveTaskRow{
		{UPID: "f2", Type: "vzdelsnapshot", Status: "OK", StartTime: 200, EndTime: 210, Node: "node-c", ID: "111"},
	}, nil)
	if len(o2.Events) != 1 {
		t.Fatalf("the clean run of the same type/guest is the recovery, got %d", len(o2.Events))
	}
	var o3 Outcome
	pveTasksEmit(&o3, []pveTaskRow{
		{UPID: "f3", Type: "vzdelsnapshot", Status: "OK", StartTime: 300, EndTime: 310, Node: "node-c", ID: "111"},
	}, nil)
	if len(o3.Events) != 0 {
		t.Fatal("a second clean run stays silent - nothing is open anymore")
	}
	var o4 Outcome
	pveTasksEmit(&o4, []pveTaskRow{
		{UPID: "f4", Type: "vzdelsnapshot", Status: "OK", StartTime: 400, EndTime: 410, Node: "node-c", ID: "222"},
	}, nil)
	if len(o4.Events) != 0 {
		t.Fatal("a guest that never failed must not emit its ok tasks")
	}
}

func TestPVETasksSeedThenEmitOnceWithDedup(t *testing.T) {
	pveState = &pveMem{seen: map[string]bool{}}
	first := []pveTaskRow{
		{UPID: "UPID:a", Type: "vzdump", Status: "OK", StartTime: 100, EndTime: 160, Node: "node-a", ID: "105"},
	}
	var o1 Outcome
	pveTasksEmit(&o1, first, nil)
	if len(o1.Events) != 0 {
		t.Fatal("first sight must seed, not emit")
	}
	second := append(first,
		pveTaskRow{UPID: "UPID:b", Type: "qmigrate", Status: "OK", StartTime: 200, EndTime: 230, Node: "node-a", ID: "107"},
		pveTaskRow{UPID: "UPID:c", Type: "vncproxy", Status: "OK", StartTime: 210, EndTime: 211},
		pveTaskRow{UPID: "UPID:d", Type: "vzdump", Status: "some error", StartTime: 300, EndTime: 0},
	)
	var o2 Outcome
	pveTasksEmit(&o2, second, nil)
	if len(o2.Events) != 1 {
		t.Fatalf("want exactly the finished migration, got %d events", len(o2.Events))
	}
	if o2.Events[0].Kind != "pve_task" || o2.Events[0].Timestamp != 230 {
		t.Fatalf("event wrong: %+v", o2.Events[0])
	}
	var o3 Outcome
	pveTasksEmit(&o3, second, nil)
	if len(o3.Events) != 0 {
		t.Fatal("re-poll must not re-emit seen tasks")
	}
}
