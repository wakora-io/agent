package defs

import (
	"fmt"
	"testing"

	"wakora.io/agent/internal/protocol"
)

func retryHosts(n int) []vhost {
	hosts := make([]vhost, n)
	for i := range hosts {
		hosts[i] = vhost{Name: fmt.Sprintf("site%d.example.com", i), Port: 443, Primary: true}
	}
	return hosts
}

func TestAFailedSiteIsProbedAgainOutsideTheWindow(t *testing.T) {
	service := "retry-test-a"
	hosts := retryHosts(10)
	primaries := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	first := map[int]bool{7: true, 8: true}
	results := make([]vhostResult, len(hosts))
	results[7].check = protocol.CheckResult{Status: "fail"}
	results[8].check = protocol.CheckResult{Status: "ok"}
	noteVhostFailures(service, first, hosts, results)

	next := map[int]bool{0: true, 1: true}
	addVhostRetries(service, primaries, hosts, next)
	if !next[7] {
		t.Fatal("the failed site must be probed again in the next cycle")
	}
	if next[8] {
		t.Fatal("a healthy site waits for its turn")
	}
}

func TestRetriesAreCapped(t *testing.T) {
	service := "retry-test-b"
	hosts := retryHosts(60)
	var primaries []int
	all := map[int]bool{}
	for i := range hosts {
		primaries = append(primaries, i)
		all[i] = true
	}
	results := make([]vhostResult, len(hosts))
	for i := range results {
		results[i].check = protocol.CheckResult{Status: "fail"}
	}
	noteVhostFailures(service, all, hosts, results)

	next := map[int]bool{}
	addVhostRetries(service, primaries, hosts, next)
	if len(next) != vhostRetryCap {
		t.Fatalf("got %d retries, want %d", len(next), vhostRetryCap)
	}
}

func TestARecoveredSiteLeavesTheRetrySet(t *testing.T) {
	service := "retry-test-c"
	hosts := retryHosts(3)
	results := make([]vhostResult, len(hosts))
	results[2].check = protocol.CheckResult{Status: "fail"}
	noteVhostFailures(service, map[int]bool{2: true}, hosts, results)
	results[2].check = protocol.CheckResult{Status: "ok"}
	noteVhostFailures(service, map[int]bool{2: true}, hosts, results)

	next := map[int]bool{}
	addVhostRetries(service, []int{0, 1, 2}, hosts, next)
	if next[2] {
		t.Fatal("a site that answered again must not be retried")
	}
}
