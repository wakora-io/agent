//go:build linux

package defs

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const drbdFixture = `[
{
  "name": "pm-aaa", "node-id": 0, "role": "Primary",
  "suspended": false, "force-io-failures": false,
  "devices": [
    { "volume": 0, "minor": 1000, "disk-state": "UpToDate", "client": false, "open": true, "quorum": true, "size": 1048576, "lower-pending": 0 }
  ],
  "connections": [
    { "peer-node-id": 1, "name": "node-b", "connection-state": "Connected", "congested": false, "peer-role": "Secondary",
      "peer_devices": [ { "volume": 0, "replication-state": "Established", "peer-disk-state": "UpToDate", "peer-client": false, "out-of-sync": 0, "percent-in-sync": 100.0 } ] },
    { "peer-node-id": 2, "name": "node-a", "connection-state": "Connected", "congested": false, "peer-role": "Secondary",
      "peer_devices": [ { "volume": 0, "replication-state": "Established", "peer-disk-state": "Diskless", "peer-client": true, "out-of-sync": 0, "percent-in-sync": 100.0 } ] }
  ]
},
{
  "name": "pm-bbb", "node-id": 0, "role": "Secondary",
  "suspended": false, "force-io-failures": false,
  "devices": [
    { "volume": 0, "minor": 1001, "disk-state": "Inconsistent", "client": false, "open": false, "quorum": true, "size": 1048576 }
  ],
  "connections": [
    { "peer-node-id": 1, "name": "node-b", "connection-state": "Connected", "congested": true, "peer-role": "Primary",
      "peer_devices": [ { "volume": 0, "replication-state": "SyncTarget", "peer-disk-state": "UpToDate", "peer-client": false, "out-of-sync": 819200, "percent-in-sync": 18.48, "estimated-seconds-to-finish": 103546000 } ] },
    { "peer-node-id": 2, "name": "node-a", "connection-state": "StandAlone", "congested": false, "peer-role": "Unknown",
      "peer_devices": [ { "volume": 0, "replication-state": "Off", "peer-disk-state": "DUnknown", "peer-client": false, "out-of-sync": 512000, "percent-in-sync": 51.2 } ] }
  ]
}
]`

func drbdParseFixture(t *testing.T) []drbdRes {
	t.Helper()
	var rs []drbdRes
	if err := json.Unmarshal([]byte(drbdFixture), &rs); err != nil {
		t.Fatalf("fixture must parse: %v", err)
	}
	return rs
}

func drbdMetric(o *Outcome, name, tagKey, tagVal string) (float64, bool) {
	for _, m := range o.Metrics {
		if m.Name != name {
			continue
		}
		if tagKey == "" || m.Tags[tagKey] == tagVal {
			return m.Value, true
		}
	}
	return 0, false
}

func TestDrbdEmitReadsStates(t *testing.T) {
	drbdMem = map[string]*drbdLinkMem{}
	rs := drbdParseFixture(t)
	o := &Outcome{}
	drbdEmit(o, "drbd", rs, time.Now())

	if o.Check.Status != "ok" {
		t.Fatalf("check must be ok, got %s %s", o.Check.Status, o.Check.Error)
	}
	if v, _ := drbdMetric(o, "svc.drbd.resources", "", ""); v != 2 {
		t.Fatalf("resources: %v", v)
	}
	if v, ok := drbdMetric(o, "svc.drbd.device.uptodate", "res", "pm-aaa"); !ok || v != 1 {
		t.Fatalf("pm-aaa must read uptodate, got %v %v", v, ok)
	}
	if v, ok := drbdMetric(o, "svc.drbd.device.uptodate", "res", "pm-bbb"); !ok || v != 0 {
		t.Fatalf("inconsistent pm-bbb must read 0, got %v %v", v, ok)
	}
	if v, _ := drbdMetric(o, "svc.drbd.resource.replicas_uptodate", "res", "pm-aaa"); v != 2 {
		t.Fatalf("pm-aaa replicas: own + node-b = 2 (the diskless tiebreaker never counts), got %v", v)
	}
	if v, _ := drbdMetric(o, "svc.drbd.resource.replicas_uptodate", "res", "pm-bbb"); v != 1 {
		t.Fatalf("pm-bbb replicas: only the node-b peer, got %v", v)
	}
	if v, _ := drbdMetric(o, "svc.drbd.connection.established", "link", "pm-bbb:node-a"); v != 0 {
		t.Fatalf("standalone link must read down, got %v", v)
	}
	if v, _ := drbdMetric(o, "svc.drbd.peer.oos_lingering_kib", "link", "pm-bbb:node-b"); v != 0 {
		t.Fatalf("oos during an active resync is not lingering, got %v", v)
	}
	if v, _ := drbdMetric(o, "svc.drbd.peer.oos_lingering_kib", "link", "pm-aaa:node-b"); v != 0 {
		t.Fatalf("clean established link lingers nothing, got %v", v)
	}
	if v, ok := drbdMetric(o, "svc.drbd.peer.resync_percent", "link", "pm-bbb:node-b"); !ok || v != 18.48 {
		t.Fatalf("resync percent must flow, got %v %v", v, ok)
	}
	if v, _ := drbdMetric(o, "svc.drbd.peer.eta_sec", "link", "pm-bbb:node-b"); v != 103546000 {
		t.Fatalf("eta must flow, got %v", v)
	}
	if o.Facts["degraded"] == "" {
		t.Fatal("the degraded fact must name pm-bbb")
	}
}

func TestDrbdStallNeedsTenFrozenMinutes(t *testing.T) {
	drbdMem = map[string]*drbdLinkMem{}
	rs := drbdParseFixture(t)
	now := time.Now()

	o1 := &Outcome{}
	drbdEmit(o1, "drbd", rs, now)
	if v, _ := drbdMetric(o1, "svc.drbd.peer.resync_stalled", "link", "pm-bbb:node-b"); v != 0 {
		t.Fatalf("first sight never stalls, got %v", v)
	}

	o2 := &Outcome{}
	drbdEmit(o2, "drbd", rs, now.Add(5*time.Minute))
	if v, _ := drbdMetric(o2, "svc.drbd.peer.resync_stalled", "link", "pm-bbb:node-b"); v != 0 {
		t.Fatalf("five frozen minutes are not a stall yet, got %v", v)
	}

	o3 := &Outcome{}
	drbdEmit(o3, "drbd", rs, now.Add(11*time.Minute))
	if v, _ := drbdMetric(o3, "svc.drbd.peer.resync_stalled", "link", "pm-bbb:node-b"); v != 1 {
		t.Fatalf("eleven frozen minutes with oos must stall, got %v", v)
	}

	moved := drbdParseFixture(t)
	moved[1].Conns[0].PeerDevs[0].Percent = 19.02
	o4 := &Outcome{}
	drbdEmit(o4, "drbd", moved, now.Add(12*time.Minute))
	if v, _ := drbdMetric(o4, "svc.drbd.peer.resync_stalled", "link", "pm-bbb:node-b"); v != 0 {
		t.Fatalf("progress clears the stall, got %v", v)
	}
}

func TestDrbdFlapsCountTransitions(t *testing.T) {
	drbdMem = map[string]*drbdLinkMem{}
	rs := drbdParseFixture(t)
	now := time.Now()

	for i := 0; i < 4; i++ {
		up := i%2 == 0
		state := "Connected"
		if !up {
			state = "Connecting"
		}
		rs[0].Conns[0].State = state
		o := &Outcome{}
		drbdEmit(o, "drbd", rs, now.Add(time.Duration(i)*time.Minute))
		if i == 3 {
			if v, _ := drbdMetric(o, "svc.drbd.connection.flaps_hour", "link", "pm-aaa:node-b"); v != 3 {
				t.Fatalf("three transitions expected, got %v", v)
			}
		}
	}
}

func TestDrbdSkipsTransientSnapshotResources(t *testing.T) {
	drbdMem = map[string]*drbdLinkMem{}
	rs := drbdParseFixture(t)
	snap := drbdParseFixture(t)[1]
	snap.Name = "snap_pm-bbb_vzdump"
	snap.Conns[0].Name = "peer-a"
	snap.Conns[0].PeerDevs[0].Repl = "Established"
	rs = append(rs, snap)

	o := &Outcome{}
	drbdEmit(o, "drbd", rs, time.Now())

	if v, _ := drbdMetric(o, "svc.drbd.resources", "", ""); v != 2 {
		t.Fatalf("a vzdump snapshot is not a monitored resource, got %v", v)
	}
	if _, ok := drbdMetric(o, "svc.drbd.peer.oos_lingering_kib", "link", "snap_pm-bbb_vzdump:peer-a"); ok {
		t.Fatal("a snapshot link must never reach the alerting rules")
	}
	if _, ok := drbdMetric(o, "svc.drbd.device.uptodate", "res", "snap_pm-bbb_vzdump"); ok {
		t.Fatal("a snapshot resource must not emit device state")
	}
	for k := range drbdMem {
		if strings.HasPrefix(k, "snap_") {
			t.Fatalf("snapshot links must not accumulate in memory, got %s", k)
		}
	}
	if v, ok := drbdMetric(o, "svc.drbd.device.uptodate", "res", "pm-aaa"); !ok || v != 1 {
		t.Fatalf("real resources keep flowing, got %v %v", v, ok)
	}
}

func TestDrbdEmptyIsHonestOk(t *testing.T) {
	o := &Outcome{}
	drbdEmit(o, "drbd", nil, time.Now())
	if o.Check.Status != "ok" || o.Check.Error != "no drbd resources configured" {
		t.Fatalf("empty must be ok with the note, got %s %s", o.Check.Status, o.Check.Error)
	}
}

func TestPveTasksEmitFailedTasks(t *testing.T) {
	pveState.seen = map[string]bool{}
	pveState.seeded = true
	o := &Outcome{}
	pveTasksEmit(o, []pveTaskRow{
		{UPID: "u1", Node: "node-a", Type: "vzstart", Status: "command failed: 401 Unauthorized", StartTime: 100, EndTime: 104, User: "root@pam", ID: "104"},
		{UPID: "u2", Node: "node-a", Type: "vzstart", Status: "OK", StartTime: 100, EndTime: 103, User: "root@pam", ID: "105"},
		{UPID: "u3", Node: "node-a", Type: "vzdump", Status: "OK", StartTime: 100, EndTime: 260, User: "root@pam", ID: "106"},
		{UPID: "u4", Node: "node-a", Type: "aptupdate", Status: "", StartTime: 100, EndTime: 0, User: "root@pam"},
	}, nil)
	if len(o.Events) != 2 {
		t.Fatalf("the failed vzstart and the ok vzdump must emit, got %d", len(o.Events))
	}
	if !pveState.seen["u1"] || !pveState.seen["u2"] || !pveState.seen["u3"] {
		t.Fatal("finished tasks must be marked seen")
	}
	if pveState.seen["u4"] {
		t.Fatal("a running task must stay unseen so its completion can emit later")
	}
}

func TestPveMigrationCarriesTheTargetNode(t *testing.T) {
	pveState.seen = map[string]bool{}
	pveState.seeded = true
	o := &Outcome{}
	logCalls := 0
	logFn := func(node, upid string) []byte {
		logCalls++
		if node != "node-a" || upid != "m1" {
			t.Fatalf("log read must name the task, got %s %s", node, upid)
		}
		return []byte(`[{"n":1,"t":"task started by HA resource agent"},{"n":2,"t":"2026-08-20 21:00:01 starting migration of CT 111 to node 'node-c' (192.0.2.2)"}]`)
	}
	pveTasksEmit(o, []pveTaskRow{
		{UPID: "m1", Node: "node-a", Type: "vzmigrate", Status: "OK", StartTime: 100, EndTime: 104, User: "root@pam", ID: "111"},
		{UPID: "b1", Node: "node-a", Type: "vzdump", Status: "OK", StartTime: 100, EndTime: 260, User: "root@pam", ID: "106"},
	}, logFn)
	if logCalls != 1 {
		t.Fatalf("only the migration reads its log, got %d reads", logCalls)
	}
	found := false
	for _, e := range o.Events {
		if strings.Contains(e.Detail, `"target":"node-c"`) {
			found = true
		}
	}
	if !found {
		t.Fatalf("the migration event must carry the target node, got %+v", o.Events)
	}
}

func TestPveTaskTargetSurvivesGarbage(t *testing.T) {
	if pveTaskTarget(nil) != "" {
		t.Fatal("nil log reads empty")
	}
	if pveTaskTarget([]byte("not json")) != "" {
		t.Fatal("garbage reads empty")
	}
	if pveTaskTarget([]byte(`[{"n":1,"t":"no target here"}]`)) != "" {
		t.Fatal("a log without the phrase reads empty")
	}
}
