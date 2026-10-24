//go:build !linux

package agent

import "wakora.io/agent/internal/protocol"

func startRunMark(string, string) (*protocol.AgentEvent, *pendingRestart) {
	return nil, nil
}

func touchRunMark() {}

func MarkCleanStop() {}
