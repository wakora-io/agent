//go:build !windows

package defs

import (
	"time"

	"wakora.io/agent/internal/protocol"
)

func (l *LogTailer) winEventLines(_ []string, _ time.Time) ([]protocol.LogLine, error) {
	return nil, nil
}
