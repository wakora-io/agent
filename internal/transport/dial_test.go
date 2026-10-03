package transport

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func withLookup(t *testing.T, ips ...string) {
	t.Helper()
	prevLookup, prevTimeout := lookupAddrs, dialPerAddress
	t.Cleanup(func() { lookupAddrs, dialPerAddress = prevLookup, prevTimeout })
	dialPerAddress = 300 * time.Millisecond
	lookupAddrs = func(context.Context, string) ([]net.IPAddr, error) {
		out := make([]net.IPAddr, 0, len(ips))
		for _, s := range ips {
			out = append(out, net.IPAddr{IP: net.ParseIP(s)})
		}
		return out, nil
	}
}

func TestDialEachMovesPastASilentAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	withLookup(t, "192.0.2.1", "127.0.0.1")
	start := time.Now()
	c, err := dialEach(context.Background(), "tcp", net.JoinHostPort("gw.example.com", port))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c.Close()
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("took %v, want the silent address to be skipped after its own timeout", took)
	}
}

func TestDialEachReportsEveryFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	ln.Close()
	withLookup(t, "127.0.0.1", "127.0.0.1")
	_, err = dialEach(context.Background(), "tcp", net.JoinHostPort("gw.example.com", port))
	if err == nil {
		t.Fatal("dial to a closed port succeeded")
	}
}

func TestDialEachSkipsLookupForALiteral(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	prev := lookupAddrs
	t.Cleanup(func() { lookupAddrs = prev })
	lookupAddrs = func(context.Context, string) ([]net.IPAddr, error) {
		return nil, errors.New("lookup must not run for an address literal")
	}
	c, err := dialEach(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c.Close()
}

func TestDialEachNoAddresses(t *testing.T) {
	withLookup(t)
	if _, err := dialEach(context.Background(), "tcp", "gw.example.com:8443"); err == nil {
		t.Fatal("dial with no addresses succeeded")
	}
}
