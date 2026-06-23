package agent

import (
	"encoding/json"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

type apmWantSet struct {
	ports []int
	down  map[string][]int
	seen  time.Time
}

const apmWantTTL = 10 * time.Minute

func (a *Agent) resolvePorts(process string) []int {
	a.mu.Lock()
	facts := a.facts
	a.mu.Unlock()
	seen := map[int]bool{}
	var out []int
	for _, f := range facts {
		if f.Kind != "port" || !strings.HasSuffix(f.Key, "/tcp") {
			continue
		}
		var info struct {
			Process string `json:"process"`
			Pid     int    `json:"pid"`
		}
		if json.Unmarshal([]byte(f.Payload), &info) != nil {
			continue
		}
		if info.Process != process && !strings.HasPrefix(info.Process, process+" ") {
			if info.Pid <= 0 {
				continue
			}
			exe, err := os.Readlink("/proc/" + strconv.Itoa(info.Pid) + "/exe")
			if err != nil || path.Base(exe) != process {
				continue
			}
		}
		p, err := strconv.Atoi(strings.TrimSuffix(f.Key, "/tcp"))
		if err != nil || p <= 0 || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

func apmUnion(want map[string]apmWantSet, now time.Time) ([]int, map[string][]int) {
	pseen := map[int]bool{}
	var ports []int
	down := map[string][]int{}
	dseen := map[string]map[int]bool{}
	for _, w := range want {
		if now.Sub(w.seen) > apmWantTTL {
			continue
		}
		for _, p := range w.ports {
			if !pseen[p] {
				pseen[p] = true
				ports = append(ports, p)
			}
		}
		for name, dp := range w.down {
			if dseen[name] == nil {
				dseen[name] = map[int]bool{}
			}
			for _, p := range dp {
				if !dseen[name][p] {
					dseen[name][p] = true
					down[name] = append(down[name], p)
				}
			}
		}
	}
	sort.Ints(ports)
	for _, dp := range down {
		sort.Ints(dp)
	}
	return ports, down
}

func intsEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func downEqual(a, b map[string][]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if !intsEqual(v, b[k]) {
			return false
		}
	}
	return true
}
