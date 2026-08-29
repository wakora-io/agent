package defs

import (
	"testing"
	"time"

	"wakora.io/agent/internal/protocol"
)

func TestJournalCountsAndCaptures(t *testing.T) {
	j := NewJournalTailer("ssh/auth")
	lines := []string{
		"Failed password for root from 192.0.2.82 port 40404 ssh2",
		"Failed password for invalid user admin from 10.0.0.5 port 22 ssh2",
		"Invalid user admin from 10.0.0.5 port 22",
		"Accepted publickey for root from 192.0.2.109 port 55555 ssh2",
	}
	counters := []protocol.Counter{
		{Name: "fail", Regex: "^(Failed |Invalid user)", Capture: `from (\d+\.\d+\.\d+\.\d+)`, Event: "ssh_bruteforce", Min: 2},
		{Name: "ok", Regex: "^Accepted "},
	}
	counts := make([]int, len(counters))
	sources := make([]map[string]int, len(counters))
	for _, line := range lines {
		j.count([]byte(line), counters, counts, sources)
	}
	if counts[0] != 3 || counts[1] != 1 {
		t.Fatalf("counts: %v", counts)
	}
	if sources[0]["10.0.0.5"] != 2 || sources[0]["192.0.2.82"] != 1 {
		t.Fatalf("sources: %v", sources[0])
	}
	ev, ok := foldSourceEvent(counters[0], sources[0], time.Now(), j.srcLast)
	if !ok || ev.Kind != "ssh_bruteforce" {
		t.Fatalf("source event: %v %v", ok, ev)
	}
}

func newTestHub() *journalHub {
	return &journalHub{subs: map[string]*journalSub{}, gen: 1, done: 1}
}

func TestJournalHubRoutesByIdent(t *testing.T) {
	h := newTestHub()
	h.subs["nginx"] = &journalSub{key: "nginx", set: map[string]bool{"nginx": true}, seeded: true}
	h.subs["ssh"] = &journalSub{key: "ssh", set: map[string]bool{"sshd": true}, seeded: true}
	out := []byte(`{"PRIORITY":"3","MESSAGE":"upstream timed out","SYSLOG_IDENTIFIER":"nginx","__REALTIME_TIMESTAMP":"1750000000000000"}
{"PRIORITY":"6","MESSAGE":"Accepted publickey","SYSLOG_IDENTIFIER":"sshd","__REALTIME_TIMESTAMP":"1750000001000000"}
{"PRIORITY":"4","MESSAGE":"unrelated","SYSLOG_IDENTIFIER":"chronyd","__REALTIME_TIMESTAMP":"1750000002000000"}
-- cursor: s=abc;i=1
`)
	h.consume(out, false, 0)
	if h.cursor != "s=abc;i=1" {
		t.Fatalf("cursor: %q", h.cursor)
	}
	q := h.subs["nginx"].queue
	if len(q) != 1 || q[0].level != "error" || q[0].msg != "upstream timed out" || q[0].ts != 1750000000 {
		t.Fatalf("nginx queue: %+v", q)
	}
	q = h.subs["ssh"].queue
	if len(q) != 1 || q[0].level != "info" {
		t.Fatalf("ssh queue: %+v", q)
	}
}

func TestJournalHubFirstRunSkipsBacklog(t *testing.T) {
	h := newTestHub()
	h.subs["nginx"] = &journalSub{key: "nginx", set: map[string]bool{"nginx": true}, seeded: true}
	out := []byte(`{"PRIORITY":"3","MESSAGE":"old line","SYSLOG_IDENTIFIER":"nginx"}
-- cursor: seed
`)
	h.consume(out, true, 0)
	if h.cursor != "seed" {
		t.Fatalf("cursor: %q", h.cursor)
	}
	if len(h.subs["nginx"].queue) != 0 {
		t.Fatal("first fetch must not deliver backlog")
	}
}

func TestJournalHubNewSubscriberSkipsItsFirstDrain(t *testing.T) {
	h := newTestHub()
	entries, err := h.drain("mysql/journal", []string{"mariadbd"})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("first drain must seed, got %d", len(entries))
	}
	h.subs["mysql/journal"].queue = []journalEntry{{ts: 1, level: "error", msg: "table crashed"}}
	entries, err = h.drain("mysql/journal", []string{"mariadbd"})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].msg != "table crashed" {
		t.Fatalf("second drain: %+v", entries)
	}
	if len(h.subs["mysql/journal"].queue) != 0 {
		t.Fatal("drain must clear the queue")
	}
}

func TestJournalHubUnionDedupesAcrossSubscribers(t *testing.T) {
	h := newTestHub()
	h.drain("system/journal", []string{"sshd", "cron"})
	h.drain("ssh/auth", []string{"sshd"})
	h.drain("nginx/journal", []string{"nginx"})
	got := h.union()
	want := []string{"cron", "nginx", "sshd"}
	if len(got) != len(want) {
		t.Fatalf("union: %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("union: %v, want %v", got, want)
		}
	}
}

func TestJournalHubDropsInvalidIdent(t *testing.T) {
	h := newTestHub()
	entries, err := h.drain("ssh/auth", []string{"sshd; rm -rf /"})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("invalid ident produced entries")
	}
	if len(h.subs["ssh/auth"].set) != 0 {
		t.Fatal("invalid ident kept in the subscriber set")
	}
	if len(h.union()) != 0 {
		t.Fatal("invalid ident reached the journalctl arguments")
	}
}

func TestJournalHubFetchRunsOncePerCycle(t *testing.T) {
	h := newTestHub()
	h.subs["a"] = &journalSub{key: "a", set: map[string]bool{"nginx": true}, seeded: true}
	h.done = h.gen - 1
	h.fetch()
	if h.done != h.gen {
		t.Fatal("fetch must mark the cycle as served")
	}
	h.cursor = "kept"
	h.fetch()
	if h.cursor != "kept" {
		t.Fatal("second fetch in the same cycle must be a no-op")
	}
}
