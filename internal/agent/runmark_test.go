package agent

import (
	"encoding/json"
	"testing"
	"time"
)

func TestRestartReasonNamesWhatHappened(t *testing.T) {
	prev := runMark{Pid: 4242, Boot: "b1", Alive: 1000, Version: "r359"}
	cases := []struct {
		name         string
		prev         runMark
		boot         string
		unit, kernel []string
		reason       string
		detail       string
	}{
		{"clean stop", runMark{Pid: 4242, Boot: "b1", Clean: true}, "b1", nil, nil, "", ""},
		{"host rebooted without stopping the agent", prev, "b2", nil, nil, "host_restart", ""},
		{"kernel named the pid", prev, "b1", nil, []string{"Memory cgroup out of memory: Killed process 4242 (wakora) total-vm:1250464kB"}, "oom", ""},
		{"systemd in a container", prev, "b1", []string{"wakora-agent.service: A process of this unit has been killed by the OOM killer."}, nil, "oom", ""},
		{"go panic", prev, "b1", []string{"goroutine 1 [running]:", "panic: runtime error: index out of range [3] with length 2", "wakora-agent.service: Main process exited, code=exited, status=2/INVALIDARGUMENT"}, nil, "panic", "panic: runtime error: index out of range [3] with length 2"},
		{"killed by a signal", prev, "b1", []string{"wakora-agent.service: Main process exited, code=killed, status=9/KILL"}, nil, "signal", "9/KILL"},
		{"go crash without its trace", prev, "b1", []string{"wakora-agent.service: Main process exited, code=exited, status=2/INVALIDARGUMENT"}, nil, "panic", ""},
		{"another pid in the kernel log", prev, "b1", nil, []string{"Out of memory: Killed process 42420 (mysqld)"}, "unknown", ""},
	}
	for _, c := range cases {
		reason, detail := restartReason(c.prev, c.boot, c.unit, c.kernel)
		if reason != c.reason || detail != c.detail {
			t.Fatalf("%s: got %q %q, want %q %q", c.name, reason, detail, c.reason, c.detail)
		}
	}
	var n restartNote
	if json.Unmarshal([]byte(restartEventDetail(prev, "oom", "", 1095)), &n) != nil || n.SilentSec != 95 || n.Version != "r359" {
		t.Fatalf("the event says how long the agent was silent: %+v", n)
	}
}

func TestPendingRestartWaitsForItsOwnUnitLines(t *testing.T) {
	start := time.Unix(2000, 0)
	p := &pendingRestart{prev: runMark{Pid: 7, Boot: "b1", Alive: 1990, Version: "r360"}, unit: "wakora-agent.service", started: start}
	if _, ok := p.decide([]string{"nginx.service: Main process exited, code=killed, status=9/KILL"}, start.Add(10*time.Second)); ok {
		t.Fatal("another unit's line must not decide the reason")
	}
	ev, ok := p.decide([]string{"wakora-agent.service: Main process exited, code=killed, status=9/KILL"}, start.Add(20*time.Second))
	if !ok || ev.Kind != "agent_restart" {
		t.Fatal("the agent's own unit line decides at once")
	}
	var n restartNote
	if json.Unmarshal([]byte(ev.Detail), &n) != nil || n.Reason != "signal" || n.SilentSec != 10 {
		t.Fatalf("got %+v", n)
	}
	q := &pendingRestart{prev: runMark{Pid: 7, Boot: "b1", Alive: 1990}, unit: "wakora-agent.service", started: start}
	ev, ok = q.decide(nil, start.Add(restartDecideWithin))
	if !ok || json.Unmarshal([]byte(ev.Detail), &n) != nil || n.Reason != "unknown" {
		t.Fatal("with no line at all the reason is honestly unknown once the wait is over")
	}
}
