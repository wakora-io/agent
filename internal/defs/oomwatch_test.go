package defs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOOMKernelLinesAreSortedByWhoseMemoryItWas(t *testing.T) {
	w := NewOOMWatch(filepath.Join(t.TempDir(), "oom-state.json"))
	w.Image = func(id string) string {
		if id == "0123456789abcdef0123456789abcdef" {
			return "nginx:alpine"
		}
		return ""
	}
	w.GuestName = func(id string) string {
		if id == "115" {
			return "web-1"
		}
		return ""
	}
	now := time.Unix(1750000000, 0)
	entries := []journalEntry{
		{ts: 1749999990, msg: "oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),cpuset=/,mems_allowed=0,global_oom,task_memcg=/system.slice/mysql.service,task=mysqld,pid=901,uid=110"},
		{ts: 1749999990, msg: "Out of memory: Killed process 901 (mysqld) total-vm:2048000kB"},
		{ts: 1749999991, msg: "oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),cpuset=/,mems_allowed=0,oom_memcg=/system.slice/docker-0123456789abcdef0123456789abcdef.scope,task_memcg=/system.slice/docker-0123456789abcdef0123456789abcdef.scope,task=nginx,pid=902,uid=0"},
		{ts: 1749999992, msg: "oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),cpuset=ns,mems_allowed=0,oom_memcg=/lxc/115,task_memcg=/lxc/115/ns/system.slice/php8.3-fpm.service,task=php-fpm8.3,pid=903,uid=33"},
		{ts: 1749999993, msg: "oom-kill:constraint=CONSTRAINT_MEMCG,oom_memcg=/kubepods/burstable/pod1,task_memcg=/kubepods/burstable/pod1/abc,task=java,pid=904,uid=0"},
		{ts: 1749999994, msg: "Out of memory: Killed process 905 (wakora) total-vm:1000kB"},
	}
	points, events := w.collect(now, false, entries)
	byName := map[string]float64{}
	for _, p := range points {
		key := p.Name
		if img := p.Tags["image"]; img != "" {
			key += "{" + img + "}"
		}
		byName[key] = p.Value
	}
	if byName["host.mem.oom_kills_15m"] != 2 {
		t.Fatalf("the host counts its own kills only (mysqld and the agent), got %v", byName)
	}
	if byName["svc.docker.group.oom_kills_15m{nginx:alpine}"] != 1 {
		t.Fatalf("a docker kill lands on its image, got %v", byName)
	}
	if len(events) != 4 {
		t.Fatalf("one event per kill, kubernetes left to its own probe, got %d", len(events))
	}
	var guest OOMKill
	for _, e := range events {
		var k OOMKill
		if json.Unmarshal([]byte(e.Detail), &k) == nil && k.Scope == "guest" {
			guest = k
		}
	}
	if guest.Guest != "115" || guest.Name != "web-1" || guest.Task != "php-fpm8.3" {
		t.Fatalf("a guest kill names the guest, got %+v", guest)
	}
	var host OOMKill
	_ = json.Unmarshal([]byte(events[0].Detail), &host)
	if host.Unit != "mysql.service" || host.Task != "mysqld" || host.Pid != 901 {
		t.Fatalf("a host kill names the unit from its cgroup, got %+v", host)
	}
}

func TestOOMContainerCounterSurvivesARestart(t *testing.T) {
	root := t.TempDir() + string(os.PathSeparator)
	cg := filepath.Join(root, "sys", "fs", "cgroup")
	if err := os.MkdirAll(cg, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(n string) {
		if err := os.WriteFile(filepath.Join(cg, "memory.events"), []byte("low 0\nhigh 0\nmax 12\noom 3\noom_kill "+n+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	state := filepath.Join(t.TempDir(), "oom-state.json")
	now := time.Unix(1750000000, 0)

	write("3")
	w := NewOOMWatch(state)
	w.root = root
	points, events := w.collect(now, true, nil)
	if len(events) != 0 || points[0].Value != 0 {
		t.Fatalf("the first reading is the baseline, not kills: %v %v", points, events)
	}

	write("4")
	r := NewOOMWatch(state)
	r.root = root
	entries := []journalEntry{{ts: now.Unix(), msg: "wakora-agent.service: A process of this unit has been killed by the OOM killer."}}
	points, events = r.collect(now.Add(2*time.Minute), true, entries)
	if len(events) != 1 || points[0].Value != 1 {
		t.Fatalf("the kill that took the agent down counts after its restart: %v %v", points, events)
	}
	var k OOMKill
	if json.Unmarshal([]byte(events[0].Detail), &k) != nil || k.Unit != "wakora-agent.service" {
		t.Fatalf("the unit named by systemd rides the kill, got %s", events[0].Detail)
	}

	points, _ = r.collect(now.Add(20*time.Minute), true, nil)
	if points[0].Value != 0 {
		t.Fatalf("a kill leaves the 15-minute window, got %v", points)
	}
}

func TestOOMDockerInsideAGuestBelongsToTheGuest(t *testing.T) {
	w := NewOOMWatch(filepath.Join(t.TempDir(), "oom-state.json"))
	w.Image = func(string) string { return "" }
	w.GuestName = func(id string) string {
		if id == "186" {
			return "web-2"
		}
		return ""
	}
	entries := []journalEntry{
		{ts: 1749999991, msg: "oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),cpuset=ns,mems_allowed=0,oom_memcg=/lxc/186/ns/system.slice/docker-fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210.scope,task_memcg=/lxc/186/ns/system.slice/docker-fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210.scope,task=tail,pid=4321,uid=0"},
	}
	points, events := w.collect(time.Unix(1750000000, 0), false, entries)
	for _, p := range points {
		if p.Value != 0 {
			t.Fatalf("the hypervisor counts nothing of its own for a guest's container, got %+v", p)
		}
	}
	var k OOMKill
	if len(events) != 1 || json.Unmarshal([]byte(events[0].Detail), &k) != nil || k.Scope != "guest" || k.Guest != "186" || k.Name != "web-2" || k.Task != "tail" {
		t.Fatalf("a container inside a guest is the guest's kill, got %v", events)
	}
}

func TestOOMDockerSeenFromInsideAContainer(t *testing.T) {
	root := t.TempDir() + string(os.PathSeparator)
	cg := filepath.Join(root, "sys", "fs", "cgroup")
	if err := os.MkdirAll(cg, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(n string) {
		if err := os.WriteFile(filepath.Join(cg, "memory.events"), []byte("oom_kill "+n+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w := NewOOMWatch(filepath.Join(t.TempDir(), "oom-state.json"))
	w.root = root
	w.Image = func(id string) string {
		if id == "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210" {
			return "alpine:latest"
		}
		return ""
	}
	now := time.Unix(1750000000, 0)
	write("0")
	w.collect(now, true, nil)
	write("1")
	entries := []journalEntry{{ts: now.Unix(), msg: "docker-fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210.scope: A process of this unit has been killed by the OOM killer."}}
	points, events := w.collect(now.Add(time.Minute), true, entries)
	byName := map[string]float64{}
	for _, p := range points {
		byName[p.Name+p.Tags["image"]] = p.Value
	}
	if byName["host.mem.oom_kills_15m"] != 0 || byName["svc.docker.group.oom_kills_15malpine:latest"] != 1 {
		t.Fatalf("a container's kill lands on its image, not on the host, got %v", byName)
	}
	var k OOMKill
	if len(events) != 1 || json.Unmarshal([]byte(events[0].Detail), &k) != nil || k.Scope != "docker" || k.Image != "alpine:latest" || k.Unit != "" {
		t.Fatalf("got %v", events)
	}
}

func TestOOMImageOfARemovedContainerFromDockerEvents(t *testing.T) {
	stream := `{"status":"start","id":"aaaa","from":"redis:7","Type":"container","Action":"start","Actor":{"ID":"aaaa","Attributes":{"image":"redis:7"}}}
{"status":"oom","id":"fedcba98","from":"alpine:latest","Type":"container","Action":"oom","Actor":{"ID":"fedcba98","Attributes":{"image":"alpine:latest"}}}
`
	if got := eventImage(strings.NewReader(stream), "fedcba98"); got != "alpine:latest" {
		t.Fatalf("the image of a container that is already gone comes from its events, got %q", got)
	}
	if got := eventImage(strings.NewReader(stream), "ffff"); got != "" {
		t.Fatalf("no event, no image, got %q", got)
	}
}

func TestOOMCounterOnCgroupV1(t *testing.T) {
	root := t.TempDir() + string(os.PathSeparator)
	cg := filepath.Join(root, "sys", "fs", "cgroup", "memory")
	if err := os.MkdirAll(cg, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cg, "memory.oom_control"), []byte("oom_kill_disable 0\nunder_oom 0\noom_kill 7\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if n, ok := readOOMCounter(root); !ok || n != 7 {
		t.Fatalf("cgroup v1 counter: %d %v", n, ok)
	}
}
