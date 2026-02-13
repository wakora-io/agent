package defs

import (
	"fmt"
	"net"
	"net/http"
	"time"

	"wakora.io/agent/internal/protocol"
)

func RunProbe(service string, p protocol.Probe) protocol.CheckResult {
	timeout := time.Duration(p.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	res := protocol.CheckResult{
		CheckID:   service + "/" + p.Name,
		Kind:      p.Type,
		Timestamp: time.Now().Unix(),
	}
	start := time.Now()
	switch p.Type {
	case "http":
		res.Target = p.URL
		client := &http.Client{Timeout: timeout}
		resp, err := client.Get(p.URL)
		if err != nil {
			res.Status = "fail"
			res.Error = err.Error()
			break
		}
		resp.Body.Close()
		want := p.ExpectStatus
		if want == 0 {
			want = 200
		}
		if resp.StatusCode == want {
			res.Status = "ok"
		} else {
			res.Status = "fail"
			res.Error = fmt.Sprintf("status %d, want %d", resp.StatusCode, want)
		}
	case "tcp":
		res.Target = p.Address
		conn, err := net.DialTimeout("tcp", p.Address, timeout)
		if err != nil {
			res.Status = "fail"
			res.Error = err.Error()
		} else {
			conn.Close()
			res.Status = "ok"
		}
	default:
		res.Status = "fail"
		res.Error = "unknown probe type " + p.Type
	}
	res.LatencyMs = float64(time.Since(start).Microseconds()) / 1000
	return res
}
