package apm

import (
	"encoding/json"
	"sort"
	"strings"
)

func DotnetTraceName(osTag, arch string) string {
	if osTag == "" || arch == "" {
		return ""
	}
	name := "dotnet-trace-" + osTag + "-" + arch
	if strings.HasPrefix(osTag, "windows") {
		name += ".exe"
	}
	return name
}

type speedscopeFile struct {
	Shared struct {
		Frames []struct {
			Name string `json:"name"`
		} `json:"frames"`
	} `json:"shared"`
	Profiles []struct {
		Type   string `json:"type"`
		Events []struct {
			Type  string  `json:"type"`
			Frame int     `json:"frame"`
			At    float64 `json:"at"`
		} `json:"events"`
	} `json:"profiles"`
}

const (
	foldedStackCap = 5000
	stackDepthCap  = 64
)

func FoldSpeedscope(data []byte) (map[string]uint32, float64, int, error) {
	var f speedscopeFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, 0, 0, err
	}
	frameName := func(i int) string {
		if i < 0 || i >= len(f.Shared.Frames) {
			return "?"
		}
		name := f.Shared.Frames[i].Name
		name = strings.ReplaceAll(name, ";", ",")
		if name == "" {
			return "?"
		}
		return name
	}
	folded := map[string]uint32{}
	totalMs := 0.0
	threads := 0
	for _, p := range f.Profiles {
		if p.Type != "evented" {
			continue
		}
		threads++
		var stack []int
		prevAt := 0.0
		for _, e := range p.Events {
			if len(stack) > 0 && e.At > prevAt {
				key := foldKey(stack, frameName)
				if key != "" {
					dur := e.At - prevAt
					totalMs += dur
					if len(folded) < foldedStackCap || folded[key] > 0 {
						folded[key] += uint32(dur + 0.5)
					}
				}
			}
			prevAt = e.At
			switch e.Type {
			case "O":
				stack = append(stack, e.Frame)
			case "C":
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
			}
		}
	}
	for k, v := range folded {
		if v == 0 {
			delete(folded, k)
		}
	}
	return folded, totalMs, threads, nil
}

func syntheticFrame(name string) bool {
	switch {
	case strings.HasPrefix(name, "Process64 "), strings.HasPrefix(name, "Process32 "),
		strings.HasPrefix(name, "Thread ("), name == "Threads",
		name == "(Non-Activities)", name == "(Activities)":
		return true
	}
	return false
}

func foldKey(stack []int, frameName func(int) string) string {
	s := stack
	if len(s) > stackDepthCap {
		s = s[len(s)-stackDepthCap:]
	}
	names := make([]string, 0, len(s))
	for _, fr := range s {
		name := frameName(fr)
		if len(names) == 0 && syntheticFrame(name) {
			continue
		}
		names = append(names, name)
	}
	return strings.Join(names, ";")
}

func ParseDotnetTracePS(out, pattern string) []int {
	var pids []int
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "dotnet-trace") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pid := 0
		for _, c := range fields[0] {
			if c < '0' || c > '9' {
				pid = -1
				break
			}
			pid = pid*10 + int(c-'0')
		}
		if pid <= 0 {
			continue
		}
		if pattern != "" && !strings.Contains(strings.ToLower(line), strings.ToLower(pattern)) {
			continue
		}
		pids = append(pids, pid)
	}
	sort.Ints(pids)
	return pids
}
