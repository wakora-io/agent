//go:build !linux

package agent

import "wakora.io/agent/internal/transport"

func (a *Agent) runServiceWatch(transport.Conn) (bool, error) {
	return false, nil
}
