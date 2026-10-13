//go:build linux

package agent

import (
	"net"
	"os"
	"testing"
)

func TestLoopbackPeerUIDNamesTheConnectingProcess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	srv := <-accepted
	defer srv.Close()
	uid, ok := loopbackPeerUID(srv.LocalAddr().(*net.TCPAddr), srv.RemoteAddr().(*net.TCPAddr))
	if !ok {
		t.Skip("sock_diag is not available here")
	}
	if uid != uint32(os.Getuid()) {
		t.Fatalf("want the test's own uid %d, got %d", os.Getuid(), uid)
	}
}
