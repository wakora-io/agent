package agent

import (
	"testing"

	"wakora.io/agent/internal/discovery"
	"wakora.io/agent/internal/protocol"
)

func TestParseUnitShow(t *testing.T) {
	out := "Id=mysql.service\nNRestarts=2\nResult=oom-kill\nExecMainStartTimestampMonotonic=900\n\nId=nginx.service\nNRestarts=0\nResult=success\nExecMainStartTimestampMonotonic=100\n"
	list := parseUnitShow(out)
	if len(list) != 2 {
		t.Fatalf("units %d", len(list))
	}
	if list[0].id != "mysql.service" || list[0].restarts != 2 || list[0].result != "oom-kill" || list[0].start != "900" {
		t.Fatalf("first %+v", list[0])
	}
	if list[1].id != "nginx.service" || list[1].start != "100" {
		t.Fatalf("second %+v", list[1])
	}
}

func TestUnitRestartsNeedsABaseline(t *testing.T) {
	seen := map[string]unitState{}
	svc := map[string]string{"mysql.service": "mysql"}
	first := []unitShow{{id: "mysql.service", start: "100", restarts: 0, result: "success"}}
	if got := unitRestarts(seen, first, svc); len(got) != 0 {
		t.Fatalf("first sight reported %v", got)
	}
	if got := unitRestarts(seen, first, svc); len(got) != 0 {
		t.Fatalf("unchanged reported %v", got)
	}
	again := []unitShow{{id: "mysql.service", start: "500", restarts: 1, result: "oom-kill"}}
	got := unitRestarts(seen, again, svc)
	if len(got) != 1 || got[0].Service != "mysql" || got[0].Result != "oom-kill" || got[0].Restarts != 1 {
		t.Fatalf("restart %+v", got)
	}
	manual := []unitShow{{id: "mysql.service", start: "800", restarts: 1, result: "success"}}
	got = unitRestarts(seen, manual, svc)
	if len(got) != 1 || got[0].Restarts != 0 {
		t.Fatalf("manual restart %+v", got)
	}
	stopped := []unitShow{{id: "mysql.service", start: "0", restarts: 1}}
	if got := unitRestarts(seen, stopped, svc); len(got) != 0 {
		t.Fatalf("stopped unit reported %v", got)
	}
}

func TestARestartedServiceStaysWatched(t *testing.T) {
	seen := map[string]unitState{}
	svc := map[string]string{"nginx.service": "nginx", "redis.service": "redis"}
	unitRestarts(seen, []unitShow{{id: "nginx.service", start: "100"}, {id: "redis.service", start: "200"}}, svc)
	units := map[string]string{}
	keepWatching(units, seen, map[string]bool{"nginx": true})
	if units["nginx.service"] != "nginx" {
		t.Fatalf("a unit whose old process is gone must stay watched, got %v", units)
	}
	if _, ok := units["redis.service"]; ok {
		t.Fatal("a service no longer active leaves the watch")
	}
	if _, ok := seen["redis.service"]; ok {
		t.Fatal("its baseline is dropped too")
	}
	got := unitRestarts(seen, []unitShow{{id: "nginx.service", start: "900", result: "success"}}, units)
	if len(got) != 1 || got[0].Service != "nginx" {
		t.Fatalf("the restart is reported, got %+v", got)
	}
}

func TestCgroupUnit(t *testing.T) {
	cases := map[string]string{
		"0::/system.slice/mysql.service\n":                                         "mysql.service",
		"12:memory:/system.slice/php8.3-fpm.service\n0::/system.slice/x.service\n": "php8.3-fpm.service",
		"0::/user.slice/user-0.slice/session-3.scope\n":                            "",
		"0::/system.slice/docker-abc.scope\n":                                      "",
	}
	for in, want := range cases {
		if got := cgroupUnit(in); got != want {
			t.Fatalf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestDefPidsAndProcessKeys(t *testing.T) {
	facts := []discovery.Fact{
		{Kind: "process", Key: "mysqld", Payload: `{"pid":10,"exe":"/usr/sbin/mysqld"}`},
		{Kind: "process", Key: "node /opt/app.js", Payload: `{"pid":20,"exe":"/usr/bin/node"}`},
		{Kind: "process", Key: "php-fpm8.3", Payload: `{"pid":30}`},
		{Kind: "process", Key: "bash", Payload: `{"pid":40}`},
		{Kind: "port", Key: "6379/tcp", Payload: `{"pid":50,"process":"redis-server"}`},
	}
	all := []protocol.Definition{
		{Service: "mysql", Match: protocol.Match{Process: "mysqld"}},
		{Service: "node", Match: protocol.Match{Process: "node"}},
		{Service: "php-fpm", Match: protocol.Match{ProcessPrefix: "php-fpm"}},
		{Service: "redis", Match: protocol.Match{Port: "6379/tcp"}},
	}
	if p := defPids(all[1], facts); len(p) != 1 || p[0] != 20 {
		t.Fatalf("node pids %v", p)
	}
	if p := defPids(all[3], facts); len(p) != 1 || p[0] != 50 {
		t.Fatalf("redis pids %v", p)
	}
	keys := defProcessKeys(all, facts)
	if len(keys) != 3 || !keys["mysqld|10"] || !keys["node /opt/app.js|20"] || !keys["php-fpm8.3|30"] {
		t.Fatalf("keys %v", keys)
	}
	moved := append([]discovery.Fact{}, facts...)
	moved[0] = discovery.Fact{Kind: "process", Key: "mysqld", Payload: `{"pid":11,"exe":"/usr/sbin/mysqld"}`}
	if sameKeys(keys, defProcessKeys(all, moved)) {
		t.Fatal("a restarted mysqld must count as a change")
	}
	if !sameKeys(keys, defProcessKeys(all, append(facts, discovery.Fact{Kind: "process", Key: "vim", Payload: `{"pid":99}`}))) {
		t.Fatal("an unrelated process must not count as a change")
	}
}
