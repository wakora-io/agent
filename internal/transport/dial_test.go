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

func addrs(ss ...string) []net.IPAddr {
	out := make([]net.IPAddr, 0, len(ss))
	for _, s := range ss {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	return out
}

func TestOrderAddrsSpreadsTheFirstAddress(t *testing.T) {
	t.Cleanup(avoided.reset)
	first := map[string]int{}
	for i := 0; i < 300; i++ {
		got := orderAddrs(addrs("192.0.2.1", "192.0.2.2", "192.0.2.3"), time.Now())
		if len(got) != 3 {
			t.Fatalf("order lost an address: %v", got)
		}
		first[got[0].IP.String()]++
	}
	if len(first) != 3 {
		t.Fatalf("every address must lead some dials, got %v", first)
	}
}

func TestOrderAddrsPutsAnAvoidedAddressLast(t *testing.T) {
	t.Cleanup(avoided.reset)
	now := time.Now()
	avoided.add("192.0.2.2", now)
	for i := 0; i < 100; i++ {
		got := orderAddrs(addrs("192.0.2.1", "192.0.2.2", "192.0.2.3"), now)
		if len(got) != 3 || got[2].IP.String() != "192.0.2.2" {
			t.Fatalf("an address that answered 5xx must go last, got %v", got)
		}
	}
	got := orderAddrs(addrs("192.0.2.2"), now)
	if len(got) != 1 {
		t.Fatal("the only address stays dialable even while set aside")
	}
}

func TestAvoidedAddressReturnsAfterAMinute(t *testing.T) {
	t.Cleanup(avoided.reset)
	now := time.Now()
	avoided.add("192.0.2.2", now.Add(-avoidFor-time.Second))
	if avoided.has("192.0.2.2", now) {
		t.Fatal("a set-aside address returns to the shuffle after the window")
	}
}

func TestDialEachNoAddresses(t *testing.T) {
	withLookup(t)
	if _, err := dialEach(context.Background(), "tcp", "gw.example.com:8443"); err == nil {
		t.Fatal("dial with no addresses succeeded")
	}
}
