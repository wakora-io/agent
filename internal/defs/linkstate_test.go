package defs

import (
	"testing"
	"time"

	"wakora.io/agent/internal/protocol"
)

func linkProbe() protocol.Probe {
	return protocol.Probe{LinkState: &protocol.LinkState{
		Oper: "dev.if.oper_status", Admin: "dev.if.admin_status", Out: "dev.if.link_lost",
	}}
}

func linkPoint(name string, idx string, v float64) protocol.MetricPoint {
	return protocol.MetricPoint{Name: name, Value: v, Tags: map[string]string{"index": idx, "port": "ether" + idx}}
}

func lostOf(o Outcome, idx string) (float64, bool) {
	for _, m := range o.Metrics {
		if m.Name == "dev.if.link_lost" && m.Tags["index"] == idx {
			return m.Value, true
		}
	}
	return 0, false
}

func TestUnusedPortNeverCountsAsLost(t *testing.T) {
	linkReset()
	p := linkProbe()
	t0 := time.Unix(1000, 0)
	for i := 0; i < 3; i++ {
		o := Outcome{Metrics: []protocol.MetricPoint{
			linkPoint("dev.if.oper_status", "5", 2),
			linkPoint("dev.if.admin_status", "5", 1),
		}}
		applyLinkState(&o, p, "192.0.2.10", t0.Add(time.Duration(i)*time.Minute))
		if v, ok := lostOf(o, "5"); !ok || v != 0 {
			t.Fatalf("a port that never carried a link cannot be lost, got %v (%v)", v, ok)
		}
	}
}

func TestLinkLostOnlyAfterTheLinkWorked(t *testing.T) {
	linkReset()
	p := linkProbe()
	t0 := time.Unix(2000, 0)

	o := Outcome{Metrics: []protocol.MetricPoint{
		linkPoint("dev.if.oper_status", "1", 1),
		linkPoint("dev.if.admin_status", "1", 1),
	}}
	applyLinkState(&o, p, "192.0.2.10", t0)
	if v, _ := lostOf(o, "1"); v != 0 {
		t.Fatalf("a working port is not lost, got %v", v)
	}

	o = Outcome{Metrics: []protocol.MetricPoint{
		linkPoint("dev.if.oper_status", "1", 2),
		linkPoint("dev.if.admin_status", "1", 1),
	}}
	applyLinkState(&o, p, "192.0.2.10", t0.Add(time.Minute))
	if v, _ := lostOf(o, "1"); v != 1 {
		t.Fatalf("a port that carried a link and went down is lost, got %v", v)
	}

	o = Outcome{Metrics: []protocol.MetricPoint{
		linkPoint("dev.if.oper_status", "1", 1),
		linkPoint("dev.if.admin_status", "1", 1),
	}}
	applyLinkState(&o, p, "192.0.2.10", t0.Add(2*time.Minute))
	if v, _ := lostOf(o, "1"); v != 0 {
		t.Fatalf("the link came back, got %v", v)
	}
}

func TestOperatorShutdownIsNotALostLink(t *testing.T) {
	linkReset()
	p := linkProbe()
	t0 := time.Unix(3000, 0)

	o := Outcome{Metrics: []protocol.MetricPoint{
		linkPoint("dev.if.oper_status", "2", 1),
		linkPoint("dev.if.admin_status", "2", 1),
	}}
	applyLinkState(&o, p, "192.0.2.10", t0)

	o = Outcome{Metrics: []protocol.MetricPoint{
		linkPoint("dev.if.oper_status", "2", 2),
		linkPoint("dev.if.admin_status", "2", 2),
	}}
	applyLinkState(&o, p, "192.0.2.10", t0.Add(time.Minute))
	if v, _ := lostOf(o, "2"); v != 0 {
		t.Fatalf("an administratively shut port is not a failure, got %v", v)
	}

	o = Outcome{Metrics: []protocol.MetricPoint{linkPoint("dev.if.oper_status", "2", 2)}}
	applyLinkState(&o, p, "192.0.2.10", t0.Add(2*time.Minute))
	if v, _ := lostOf(o, "2"); v != 0 {
		t.Fatalf("the port was already retired from service, got %v", v)
	}
}

func TestLinkMemoryKeepsDevicesApart(t *testing.T) {
	linkReset()
	p := linkProbe()
	t0 := time.Unix(4000, 0)

	up := Outcome{Metrics: []protocol.MetricPoint{linkPoint("dev.if.oper_status", "1", 1)}}
	applyLinkState(&up, p, "192.0.2.10", t0)

	other := Outcome{Metrics: []protocol.MetricPoint{linkPoint("dev.if.oper_status", "1", 2)}}
	applyLinkState(&other, p, "192.0.2.20", t0.Add(time.Minute))
	if v, _ := lostOf(other, "1"); v != 0 {
		t.Fatalf("port 1 of a neighbour device must not inherit our history, got %v", v)
	}
}

func TestLinkStateIsInertWithoutADeclaration(t *testing.T) {
	linkReset()
	o := Outcome{Metrics: []protocol.MetricPoint{linkPoint("dev.if.oper_status", "1", 2)}}
	applyLinkState(&o, protocol.Probe{}, "192.0.2.10", time.Unix(5000, 0))
	if len(o.Metrics) != 1 {
		t.Fatalf("a probe without a declaration emits nothing extra, got %+v", o.Metrics)
	}
}
