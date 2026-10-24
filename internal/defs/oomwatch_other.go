//go:build !linux

package defs

import (
	"time"

	"wakora.io/agent/internal/protocol"
)

func (w *OOMWatch) Run(time.Time) ([]protocol.MetricPoint, []protocol.AgentEvent) {
	return nil, nil
}

func DockerImageOf(string) string {
	return ""
}
