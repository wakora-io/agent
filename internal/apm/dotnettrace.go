package apm

import (
	"encoding/json"
	"runtime"
	"sort"
	"strings"
)

func DotnetTraceName(osTag, arch string) string {
	if osTag == "" || arch == "" {
		return ""
	}
	name := "dotnet-trace-" + osTag + "-" + arch
	if runtime.GOOS == "windows" {
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

// FoldSpeedscope turns a dotnet-trace speedscope export (evented profiles, one per
// thread) into folded stacks weighted by milliseconds spent with that exact stack.
func FoldSpeedscope(data []byte) (map[string]uint32, float64, error) {
	var f speedscopeFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, 0, err
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
	for _, p := range f.Profiles {
		if p.Type != "evented" {
			continue
		}
		var stack []int
		prevAt := 0.0
		for _, e := range p.Events {
			if len(stack) > 0 && e.At > prevAt {
				dur := e.At - prevAt
				totalMs += dur
				if len(folded) < foldedStackCap || folded[foldKey(stack, frameName)] > 0 {
					folded[foldKey(stack, frameName)] += uint32(dur + 0.5)
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
	return folded, totalMs, nil
}

func foldKey(stack []int, frameName func(int) string) string {
	s := stack
	if len(s) > stackDepthCap {
		s = s[len(s)-stackDepthCap:]
	}
	names := make([]string, len(s))
	for i, fr := range s {
		names[i] = frameName(fr)
	}
	return strings.Join(names, ";")
}

// ParseDotnetTracePS extracts candidate pids from `dotnet-trace ps` output, keeping
// only lines whose process name/path matches the pattern (empty = any).
func ParseDotnetTracePS(out, pattern string) []int {
	var pids []int
	for _, line := range strings.Split(out, "\n") {
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
