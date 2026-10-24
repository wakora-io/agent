package agent

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"wakora.io/agent/internal/protocol"
)

type runMark struct {
	Pid     int    `json:"pid"`
	Boot    string `json:"boot"`
	Alive   int64  `json:"alive"`
	Clean   bool   `json:"clean"`
	Version string `json:"version"`
}

type restartNote struct {
	Reason    string `json:"reason"`
	Detail    string `json:"detail,omitempty"`
	SilentSec int64  `json:"silentSec"`
	Version   string `json:"version,omitempty"`
}

func restartReason(prev runMark, boot string, unitLines, kernelLines []string) (string, string) {
	if prev.Clean {
		return "", ""
	}
	if prev.Boot != "" && boot != "" && prev.Boot != boot {
		return "host_restart", ""
	}
	killed := "Killed process " + strconv.Itoa(prev.Pid) + " "
	for _, l := range kernelLines {
		if prev.Pid > 0 && strings.Contains(l, killed) {
			return "oom", ""
		}
	}
	for _, l := range unitLines {
		if strings.Contains(l, "killed by the OOM killer") || strings.Contains(l, "'oom-kill'") {
			return "oom", ""
		}
	}
	for _, l := range unitLines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "panic:") || strings.HasPrefix(t, "fatal error:") {
			if len(t) > 200 {
				t = t[:200]
			}
			return "panic", t
		}
	}
	for _, l := range unitLines {
		if i := strings.Index(l, "code=killed, status="); i >= 0 {
			sig := strings.TrimRight(strings.TrimSpace(l[i+len("code=killed, status="):]), ".")
			return "signal", sig
		}
		if strings.Contains(l, "code=exited, status=2/") {
			return "panic", ""
		}
	}
	return "unknown", ""
}

const restartDecideWithin = 150 * time.Second

type pendingRestart struct {
	prev    runMark
	unit    string
	started time.Time
}

func (p *pendingRestart) decide(lines []string, now time.Time) (protocol.AgentEvent, bool) {
	var unitLines []string
	if p.unit != "" {
		for _, l := range lines {
			if strings.HasPrefix(l, p.unit+":") {
				unitLines = append(unitLines, l)
			}
		}
	}
	if len(unitLines) == 0 && now.Sub(p.started) < restartDecideWithin {
		return protocol.AgentEvent{}, false
	}
	reason, detail := restartReason(p.prev, p.prev.Boot, unitLines, lines)
	return protocol.AgentEvent{Kind: "agent_restart", Detail: restartEventDetail(p.prev, reason, detail, p.started.Unix()), Timestamp: now.Unix()}, true
}

func restartEventDetail(prev runMark, reason, detail string, now int64) string {
	silent := now - prev.Alive
	if prev.Alive == 0 || silent < 0 {
		silent = 0
	}
	raw, _ := json.Marshal(restartNote{Reason: reason, Detail: detail, SilentSec: silent, Version: prev.Version})
	return string(raw)
}
