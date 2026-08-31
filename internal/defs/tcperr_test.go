package defs

import (
	"errors"
	"net"
	"strings"
	"testing"

	"wakora.io/agent/internal/protocol"
)

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "dial tcp 127.0.0.1:25: i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestTcpDialErrorExplainsBoundButNotAccepting(t *testing.T) {
	var err error = timeoutErr{}
	got := tcpDialError(err, protocol.Probe{PortBound: true})
	if !strings.Contains(got, "bound but the service is not accepting") {
		t.Fatalf("got %q", got)
	}
}

func TestTcpDialErrorLeavesPlainRefusedAlone(t *testing.T) {
	err := errors.New("dial tcp 127.0.0.1:3306: connect: connection refused")
	if got := tcpDialError(err, protocol.Probe{}); got != err.Error() {
		t.Fatalf("got %q", got)
	}
}

func TestTcpDialErrorNamesTheStaleConfiguredPort(t *testing.T) {
	err := errors.New("dial tcp 127.0.0.1:22000: connect: connection refused")
	got := tcpDialError(err, protocol.Probe{PortStale: "22000"})
	if !strings.Contains(got, "announces port 22000") {
		t.Fatalf("got %q", got)
	}
}

func TestTcpDialErrorTimeoutWithoutABoundPortStaysRaw(t *testing.T) {
	var err error = timeoutErr{}
	if got := tcpDialError(err, protocol.Probe{}); got != err.Error() {
		t.Fatalf("got %q", got)
	}
}

var _ net.Error = timeoutErr{}
