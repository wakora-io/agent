package agent

import "testing"

func TestChooseListenAddrPrefersLoopbackWhenPresent(t *testing.T) {
	if got := chooseListenAddr([]string{"192.0.2.10", "127.0.0.1"}, "3306"); got != "127.0.0.1:3306" {
		t.Fatalf("got %s", got)
	}
}

func TestChooseListenAddrTreatsWildcardAsLoopback(t *testing.T) {
	for _, w := range []string{"0.0.0.0", "::", "*", ""} {
		if got := chooseListenAddr([]string{w}, "80"); got != "127.0.0.1:80" {
			t.Fatalf("wildcard %q gave %s", w, got)
		}
	}
}

func TestChooseListenAddrTakesTheBoundAddress(t *testing.T) {
	if got := chooseListenAddr([]string{"192.0.2.10"}, "3306"); got != "192.0.2.10:3306" {
		t.Fatalf("got %s", got)
	}
}

func TestChooseListenAddrPrefersIPv4AmongBoundAddresses(t *testing.T) {
	if got := chooseListenAddr([]string{"2001:db8::5", "192.0.2.10"}, "9000"); got != "192.0.2.10:9000" {
		t.Fatalf("got %s", got)
	}
}

func TestChooseListenAddrBracketsIPv6(t *testing.T) {
	if got := chooseListenAddr([]string{"2001:db8::5"}, "9000"); got != "[2001:db8::5]:9000" {
		t.Fatalf("got %s", got)
	}
}

func TestChooseListenAddrEmptyWhenNothingListens(t *testing.T) {
	if got := chooseListenAddr(nil, "3306"); got != "" {
		t.Fatalf("got %s", got)
	}
}
