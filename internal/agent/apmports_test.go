package agent

import (
	"testing"
	"time"

	"wakora.io/agent/internal/discovery"
)

func TestResolvePorts(t *testing.T) {
	a := &Agent{facts: []discovery.Fact{
		{Kind: "port", Key: "3000/tcp", Payload: `{"process":"node","pid":11}`},
		{Kind: "port", Key: "3002/tcp", Payload: `{"process":"node","pid":12}`},
		{Kind: "port", Key: "3001/tcp", Payload: `{"process":"node","pid":13}`},
		{Kind: "port", Key: "3010/tcp", Payload: `{"process":"node /opt/pm2ap","pid":14}`},
		{Kind: "port", Key: "9100/tcp", Payload: `{"process":"node_exporter","pid":15}`},
		{Kind: "port", Key: "5353/udp", Payload: `{"process":"node","pid":11}`},
		{Kind: "port", Key: "80/tcp", Payload: `{"process":"nginx","pid":20}`},
		{Kind: "port", Key: "bogus", Payload: `{"process":"node"}`},
		{Kind: "process", Key: "node", Payload: `{}`},
	}}
	got := a.resolvePorts("node")
	want := []int{3000, 3001, 3002, 3010}
	if !intsEqual(got, want) {
		t.Fatalf("resolvePorts = %v, want %v", got, want)
	}
	if p := a.resolvePorts("ghost"); len(p) != 0 {
		t.Fatalf("ghost process resolved ports %v", p)
	}
}

func TestApmUnion(t *testing.T) {
	now := time.Now()
	want := map[string]apmWantSet{
		"apm-http": {ports: []int{443, 80}, down: map[string][]int{"db": {3306, 5432}, "ext": {443}}, seen: now},
		"apm-node": {ports: []int{3000, 80}, down: map[string][]int{"db": {3306}, "cache": {6379}}, seen: now},
	}
	ports, down := apmUnion(want, now)
	if !intsEqual(ports, []int{80, 443, 3000}) {
		t.Fatalf("union ports = %v", ports)
	}
	if !intsEqual(down["db"], []int{3306, 5432}) || !intsEqual(down["cache"], []int{6379}) || !intsEqual(down["ext"], []int{443}) {
		t.Fatalf("union down = %v", down)
	}
}

func TestApmUnionExpiresStaleWant(t *testing.T) {
	now := time.Now()
	want := map[string]apmWantSet{
		"apm-http": {ports: []int{80}, seen: now},
		"apm-node": {ports: []int{3000}, seen: now.Add(-apmWantTTL - time.Minute)},
	}
	ports, _ := apmUnion(want, now)
	if !intsEqual(ports, []int{80}) {
		t.Fatalf("stale want survived: %v", ports)
	}
}

func TestDownEqual(t *testing.T) {
	a := map[string][]int{"db": {3306}, "ext": {443}}
	b := map[string][]int{"db": {3306}, "ext": {443}}
	if !downEqual(a, b) {
		t.Fatal("equal maps reported different")
	}
	b["db"] = []int{3306, 5432}
	if downEqual(a, b) {
		t.Fatal("different maps reported equal")
	}
	if downEqual(a, map[string][]int{"db": {3306}}) {
		t.Fatal("different sizes reported equal")
	}
}
