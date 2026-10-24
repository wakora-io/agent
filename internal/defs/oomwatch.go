package defs

import (
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"wakora.io/agent/internal/atomicfile"
	"wakora.io/agent/internal/protocol"
)

const (
	oomWindow  = 15 * time.Minute
	oomKeep    = 30 * time.Minute
	oomEvery   = time.Minute
	oomEventsN = 20
)

type OOMKill struct {
	Ts    int64  `json:"-"`
	Scope string `json:"scope"`
	Task  string `json:"task,omitempty"`
	Pid   int    `json:"pid,omitempty"`
	Unit  string `json:"unit,omitempty"`
	Image string `json:"image,omitempty"`
	Guest string `json:"guest,omitempty"`
	Name  string `json:"name,omitempty"`
}

type oomState struct {
	Counter     uint64             `json:"counter"`
	HaveCounter bool               `json:"haveCounter"`
	Kills       []int64            `json:"kills"`
	Docker      map[string][]int64 `json:"docker"`
}

type OOMWatch struct {
	path      string
	root      string
	st        oomState
	sent      time.Time
	lines     []string
	GuestName func(id string) string
	Image     func(id string) string
}

func (w *OOMWatch) Lines() []string {
	return w.lines
}

func NewOOMWatch(path string) *OOMWatch {
	w := &OOMWatch{path: path, root: "/"}
	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, &w.st)
	}
	if w.st.Docker == nil {
		w.st.Docker = map[string][]int64{}
	}
	return w
}

var (
	oomKilledRe = regexp.MustCompile(`Killed process (\d+) \(([^)]*)\)`)
	oomUnitRe   = regexp.MustCompile(`^([^\s:]+\.(?:service|scope)): (?:A process of this unit has been killed by the OOM killer|Failed with result 'oom-kill')`)
	oomDockerRe = regexp.MustCompile(`(?:docker[-/]|libpod-)([0-9a-f]{12,64})`)
	oomLxcRe    = regexp.MustCompile(`(?:^|/)lxc/([^/]+)|lxc\.payload\.([^/]+)`)
	oomMachRe   = regexp.MustCompile(`machine\.slice/machine-([^/]+)\.scope`)
)

func oomKernelLine(msg string) (map[string]string, bool) {
	i := strings.Index(msg, "oom-kill:")
	if i < 0 {
		return nil, false
	}
	kv := map[string]string{}
	for _, part := range strings.Split(msg[i+len("oom-kill:"):], ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok {
			kv[k] = v
		}
	}
	return kv, true
}

func oomClassify(memcg string) (scope, id string) {
	if strings.Contains(memcg, "kubepods") {
		return "k8s", ""
	}
	if m := oomDockerRe.FindStringSubmatch(memcg); m != nil {
		return "docker", m[1]
	}
	if m := oomLxcRe.FindStringSubmatch(memcg); m != nil {
		if m[1] != "" {
			return "guest", m[1]
		}
		return "guest", m[2]
	}
	if m := oomMachRe.FindStringSubmatch(memcg); m != nil {
		return "guest", strings.ReplaceAll(m[1], `\x2d`, "-")
	}
	return "host", ""
}

func oomUnitOf(memcg string) string {
	for _, seg := range strings.Split(memcg, "/") {
		if strings.HasSuffix(seg, ".service") {
			return seg
		}
	}
	return ""
}

func (w *OOMWatch) parseLines(entries []journalEntry) ([]OOMKill, []string) {
	var kills []OOMKill
	var units []string
	seen := map[int]bool{}
	for _, e := range entries {
		if m := oomUnitRe.FindStringSubmatch(e.msg); m != nil {
			if !slices.Contains(units, m[1]) {
				units = append(units, m[1])
			}
			continue
		}
		if kv, ok := oomKernelLine(e.msg); ok {
			memcg := kv["task_memcg"]
			if memcg == "" {
				memcg = kv["oom_memcg"]
			}
			scope, id := oomClassify(memcg)
			if scope == "k8s" {
				continue
			}
			pid, _ := strconv.Atoi(kv["pid"])
			k := OOMKill{Ts: e.ts, Scope: scope, Task: kv["task"], Pid: pid}
			switch scope {
			case "docker":
				k.Image = "unknown"
				if w.Image != nil {
					if img := w.Image(id); img != "" {
						k.Image = img
					}
				}
			case "guest":
				k.Guest = id
				if w.GuestName != nil {
					k.Name = w.GuestName(id)
				}
			default:
				k.Unit = oomUnitOf(memcg)
			}
			if pid > 0 {
				seen[pid] = true
			}
			kills = append(kills, k)
			continue
		}
		if m := oomKilledRe.FindStringSubmatch(e.msg); m != nil {
			pid, _ := strconv.Atoi(m[1])
			if seen[pid] {
				continue
			}
			seen[pid] = true
			kills = append(kills, OOMKill{Ts: e.ts, Scope: "host", Task: m[2], Pid: pid})
		}
	}
	return kills, units
}

func readOOMCounter(root string) (uint64, bool) {
	if raw, err := os.ReadFile(root + "sys/fs/cgroup/memory.events"); err == nil {
		return oomField(string(raw), "oom_kill")
	}
	if raw, err := os.ReadFile(root + "sys/fs/cgroup/memory/memory.oom_control"); err == nil {
		return oomField(string(raw), "oom_kill")
	}
	return 0, false
}

func oomField(text, key string) (uint64, bool) {
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == key {
			n, err := strconv.ParseUint(f[1], 10, 64)
			return n, err == nil
		}
	}
	return 0, false
}

func (w *OOMWatch) counterKills(now int64) ([]OOMKill, bool) {
	c, ok := readOOMCounter(w.root)
	if !ok {
		return nil, false
	}
	var delta uint64
	switch {
	case !w.st.HaveCounter:
	case c >= w.st.Counter:
		delta = c - w.st.Counter
	default:
		delta = c
	}
	w.st.Counter, w.st.HaveCounter = c, true
	if delta > 1000 {
		delta = 1000
	}
	kills := make([]OOMKill, 0, delta)
	for i := uint64(0); i < delta; i++ {
		kills = append(kills, OOMKill{Ts: now, Scope: "host"})
	}
	return kills, true
}

func (w *OOMWatch) collect(now time.Time, container bool, entries []journalEntry) ([]protocol.MetricPoint, []protocol.AgentEvent) {
	before, _ := json.Marshal(w.st)
	kills, units := w.parseLines(entries)
	if container {
		counted, ok := w.counterKills(now.Unix())
		if !ok {
			return nil, nil
		}
		for i := range counted {
			if i < len(units) {
				counted[i].Unit = units[i]
			}
		}
		kills = counted
	} else if len(units) == 1 {
		for i := range kills {
			if kills[i].Scope == "host" && kills[i].Unit == "" {
				kills[i].Unit = units[0]
			}
		}
	}
	var events []protocol.AgentEvent
	for _, k := range kills {
		switch k.Scope {
		case "host":
			w.st.Kills = append(w.st.Kills, k.Ts)
		case "docker":
			w.st.Docker[k.Image] = append(w.st.Docker[k.Image], k.Ts)
		}
		if len(events) < oomEventsN {
			if detail, err := json.Marshal(k); err == nil {
				events = append(events, protocol.AgentEvent{Kind: "oom_kill", Detail: string(detail), Timestamp: k.Ts})
			}
		}
	}
	cut := now.Add(-oomWindow).Unix()
	w.st.Kills = oomPrune(w.st.Kills, cut)
	var points []protocol.MetricPoint
	if len(kills) > 0 || w.sent.IsZero() || now.Sub(w.sent) >= oomEvery {
		w.sent = now
		points = append(points, protocol.MetricPoint{Name: "host.mem.oom_kills_15m", Value: float64(len(w.st.Kills))})
		images := make([]string, 0, len(w.st.Docker))
		for img := range w.st.Docker {
			images = append(images, img)
		}
		sort.Strings(images)
		keep := now.Add(-oomKeep).Unix()
		for _, img := range images {
			ts := oomPrune(w.st.Docker[img], keep)
			if len(ts) == 0 {
				delete(w.st.Docker, img)
				continue
			}
			w.st.Docker[img] = ts
			n := 0
			for _, t := range ts {
				if t >= cut {
					n++
				}
			}
			points = append(points, protocol.MetricPoint{Name: "svc.docker.group.oom_kills_15m", Value: float64(n), Tags: map[string]string{"image": img}})
		}
	}
	if after, _ := json.Marshal(w.st); string(after) != string(before) && w.path != "" {
		_ = atomicfile.Write(w.path, after, 0o600)
	}
	return points, events
}

func oomPrune(ts []int64, cut int64) []int64 {
	out := ts[:0]
	for _, t := range ts {
		if t >= cut {
			out = append(out, t)
		}
	}
	return out
}
