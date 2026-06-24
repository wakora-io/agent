package agent

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"time"

	"wakora.io/agent/internal/atomicfile"
	"wakora.io/agent/internal/buildinfo"
	"wakora.io/agent/internal/transport"
)

type runtimeStatus struct {
	ConnectedNow  bool   `json:"connectedNow"`
	LastConnectAt int64  `json:"lastConnectAt"`
	LastAckAt     int64  `json:"lastAckAt"`
	LastRotateAt  int64  `json:"lastRotateAt"`
	LastError     string `json:"lastError"`
	RingPending   int64  `json:"ringPending"`
	Endpoint      string `json:"endpoint"`
	Version       string `json:"version"`
	Pin           string `json:"pin"`
	Baseline      bool   `json:"baseline"`
	WrittenAt     int64  `json:"writtenAt"`
}

func (a *Agent) statusPath() string {
	return filepath.Join(a.cfg.StateDir(), "status.json")
}

func (a *Agent) RecordDialError(err error) {
	switch {
	case errors.Is(err, transport.ErrDeregistered):
		a.lastError.Store("deregistered")
	case errors.Is(err, transport.ErrUnauthorized):
		a.lastError.Store("unauthorized")
	case err != nil:
		a.lastError.Store("network: " + err.Error())
	default:
		a.lastError.Store("")
	}
	a.writeStatus()
}

func (a *Agent) writeStatus() {
	le, _ := a.lastError.Load().(string)
	s := runtimeStatus{
		ConnectedNow:  a.connected.Load(),
		LastConnectAt: a.lastConnect.Load(),
		LastAckAt:     a.lastAck.Load(),
		LastRotateAt:  a.lastRotate.Load(),
		LastError:     le,
		RingPending:   a.ring.Size(),
		Endpoint:      a.cfg.Endpoint,
		Version:       buildinfo.Version,
		Pin:           a.EffectivePin(),
		Baseline:      a.cfg.Baseline,
		WrittenAt:     time.Now().Unix(),
	}
	data, err := json.Marshal(s)
	if err != nil {
		return
	}
	_ = atomicfile.Write(a.statusPath(), data, 0o644)
}
