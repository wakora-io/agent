//go:build linux

package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"wakora.io/agent/internal/atomicfile"
	"wakora.io/agent/internal/protocol"
)

var (
	markMu   sync.Mutex
	markPath string
	markCur  runMark
)

func bootID() string {
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

func writeMark() {
	if markPath == "" {
		return
	}
	if raw, err := json.Marshal(markCur); err == nil {
		_ = atomicfile.Write(markPath, raw, 0o600)
	}
}

func startRunMark(stateDir, version string) (*protocol.AgentEvent, *pendingRestart) {
	markMu.Lock()
	defer markMu.Unlock()
	markPath = filepath.Join(stateDir, "run-mark.json")
	var prev runMark
	havePrev := false
	if raw, err := os.ReadFile(markPath); err == nil && json.Unmarshal(raw, &prev) == nil {
		havePrev = true
	}
	now := time.Now()
	boot := bootID()
	markCur = runMark{Pid: os.Getpid(), Boot: boot, Alive: now.Unix(), Version: version}
	writeMark()
	if !havePrev || prev.Clean {
		return nil, nil
	}
	if prev.Boot != "" && boot != "" && prev.Boot != boot {
		return &protocol.AgentEvent{Kind: "agent_restart", Detail: restartEventDetail(prev, "host_restart", "", now.Unix()), Timestamp: now.Unix()}, nil
	}
	unit, _, _ := selfServiceCgroup()
	return nil, &pendingRestart{prev: prev, unit: unit, started: now}
}

func touchRunMark() {
	markMu.Lock()
	defer markMu.Unlock()
	if markPath == "" || markCur.Clean {
		return
	}
	markCur.Alive = time.Now().Unix()
	writeMark()
}

func MarkCleanStop() {
	markMu.Lock()
	defer markMu.Unlock()
	if markPath == "" {
		return
	}
	markCur.Alive = time.Now().Unix()
	markCur.Clean = true
	writeMark()
}
