package agent

import (
	"encoding/json"
	"path"
	"strconv"
	"strings"

	"wakora.io/agent/internal/discovery"
	"wakora.io/agent/internal/protocol"
)

type unitState struct {
	start    string
	restarts int
	service  string
}

type unitShow struct {
	id       string
	start    string
	restarts int
	result   string
}

type serviceRestart struct {
	Unit     string `json:"unit"`
	Service  string `json:"service,omitempty"`
	Result   string `json:"result,omitempty"`
	Restarts int    `json:"autoRestarts"`
}

func parseUnitShow(out string) []unitShow {
	var list []unitShow
	cur := unitShow{}
	flush := func() {
		if cur.id != "" {
			list = append(list, cur)
		}
		cur = unitShow{}
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			flush()
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "Id":
			cur.id = v
		case "NRestarts":
			cur.restarts, _ = strconv.Atoi(v)
		case "Result":
			cur.result = v
		case "ExecMainStartTimestampMonotonic":
			cur.start = v
		}
	}
	flush()
	return list
}

func unitRestarts(seen map[string]unitState, shows []unitShow, service map[string]string) []serviceRestart {
	var out []serviceRestart
	for _, s := range shows {
		prev, ok := seen[s.id]
		seen[s.id] = unitState{start: s.start, restarts: s.restarts, service: service[s.id]}
		if !ok || s.start == "" || s.start == "0" || s.start == prev.start {
			continue
		}
		auto := s.restarts - prev.restarts
		if auto < 0 {
			auto = 0
		}
		out = append(out, serviceRestart{Unit: s.id, Service: service[s.id], Result: s.result, Restarts: auto})
	}
	return out
}

func cgroupUnit(cgroup string) string {
	unit := ""
	for _, line := range strings.Split(cgroup, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		for _, seg := range strings.Split(parts[2], "/") {
			if strings.HasSuffix(seg, ".service") {
				unit = seg
			}
		}
		if unit != "" {
			return unit
		}
	}
	return ""
}

func defPids(d protocol.Definition, facts []discovery.Fact) []int {
	m := d.Match
	var pids []int
	add := func(payload string) {
		var info struct {
			Pid int    `json:"pid"`
			Exe string `json:"exe"`
		}
		if json.Unmarshal([]byte(payload), &info) == nil && info.Pid > 0 {
			pids = append(pids, info.Pid)
		}
	}
	for _, f := range facts {
		switch {
		case f.Kind == "process" && m.Process != "":
			if f.Key == m.Process {
				add(f.Payload)
				continue
			}
			var info struct {
				Exe string `json:"exe"`
			}
			if json.Unmarshal([]byte(f.Payload), &info) == nil && info.Exe != "" && path.Base(info.Exe) == m.Process {
				add(f.Payload)
			}
		case f.Kind == "process" && m.ProcessPrefix != "" && strings.HasPrefix(f.Key, m.ProcessPrefix):
			add(f.Payload)
		case f.Kind == "port" && m.Port != "" && f.Key == m.Port:
			add(f.Payload)
		}
	}
	return pids
}

func keepWatching(units map[string]string, seen map[string]unitState, active map[string]bool) {
	for id, st := range seen {
		if !active[st.service] {
			delete(seen, id)
			continue
		}
		if _, ok := units[id]; !ok {
			units[id] = st.service
		}
	}
}

func defProcessKeys(all []protocol.Definition, facts []discovery.Fact) map[string]bool {
	out := map[string]bool{}
	for _, f := range facts {
		if f.Kind != "process" {
			continue
		}
		var info struct {
			Pid int    `json:"pid"`
			Exe string `json:"exe"`
		}
		_ = json.Unmarshal([]byte(f.Payload), &info)
		base := ""
		if info.Exe != "" {
			base = path.Base(info.Exe)
		}
		for _, d := range all {
			m := d.Match
			if (m.Process != "" && (f.Key == m.Process || base == m.Process)) || (m.ProcessPrefix != "" && strings.HasPrefix(f.Key, m.ProcessPrefix)) {
				out[f.Key+"|"+strconv.Itoa(info.Pid)] = true
				break
			}
		}
	}
	return out
}

func sameKeys(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func restartEvent(r serviceRestart, now int64) protocol.AgentEvent {
	raw, _ := json.Marshal(r)
	return protocol.AgentEvent{Kind: "service_restart", Detail: string(raw), Timestamp: now}
}
