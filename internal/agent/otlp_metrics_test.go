package agent

import "testing"

func TestNodeMetricName(t *testing.T) {
	cases := []struct {
		name  string
		unit  string
		want  string
		scale float64
		ok    bool
	}{
		{"nodejs.eventloop.utilization", "1", "svc.node.nodejs_eventloop_utilization", 1, true},
		{"nodejs.eventloop.delay.mean", "s", "svc.node.nodejs_eventloop_delay_mean_ms", 1000, true},
		{"v8js.memory.heap.used", "By", "svc.node.v8js_memory_heap_used", 1, true},
		{"v8js.gc.duration", "s", "svc.node.v8js_gc_duration_ms", 1000, true},
		{"http.server.duration", "s", "", 0, false},
		{"system.cpu.time", "s", "", 0, false},
	}
	for _, c := range cases {
		name, scale, ok := nodeMetricName(c.name, c.unit)
		if ok != c.ok || name != c.want || scale != c.scale {
			t.Fatalf("nodeMetricName(%q,%q) = (%q,%v,%v), want (%q,%v,%v)", c.name, c.unit, name, scale, ok, c.want, c.scale, c.ok)
		}
	}
}

func TestConvertOTLPMetricsJSON(t *testing.T) {
	d := func(v float64) *float64 { return &v }
	exp := otlpMetricsExport{ResourceMetrics: []otlpResourceMetrics{{
		Resource: otlpResource{Attributes: []otlpKV{{Key: "service.name", Value: otlpAny{StringValue: strptr("nodeapp")}}}},
		ScopeMetrics: []otlpScopeMetrics{{Metrics: []otlpMetric{
			{Name: "nodejs.eventloop.utilization", Unit: "1", Gauge: &otlpMetricData{DataPoints: []otlpNumberDP{{AsDouble: d(0.03)}}}},
			{Name: "nodejs.eventloop.delay.mean", Unit: "s", Gauge: &otlpMetricData{DataPoints: []otlpNumberDP{{AsDouble: d(0.012)}}}},
			{Name: "v8js.memory.heap.used", Unit: "By", Sum: &otlpMetricData{DataPoints: []otlpNumberDP{{AsInt: []byte(`"1048576"`)}, {AsInt: []byte(`"2097152"`)}}}},
			{Name: "v8js.gc.duration", Unit: "s", Histogram: &otlpMetricData{DataPoints: []otlpNumberDP{{Sum: d(0.02), Count: []byte("4")}}}},
			{Name: "http.server.duration", Unit: "s", Gauge: &otlpMetricData{DataPoints: []otlpNumberDP{{AsDouble: d(1)}}}},
		}}},
	}}}
	pts := convertOTLPMetrics(exp)
	got := map[string]float64{}
	for _, p := range pts {
		if p.Tags["unit"] != "nodeapp" {
			t.Fatalf("unit tag = %q", p.Tags["unit"])
		}
		got[p.Name] = p.Value
	}
	if len(got) != 4 {
		t.Fatalf("emitted %d points, want 4: %v", len(got), got)
	}
	if got["svc.node.nodejs_eventloop_utilization"] != 0.03 {
		t.Fatalf("utilization = %v", got["svc.node.nodejs_eventloop_utilization"])
	}
	if v := got["svc.node.nodejs_eventloop_delay_mean_ms"]; v < 11.9 || v > 12.1 {
		t.Fatalf("delay ms = %v, want ~12", v)
	}
	if got["svc.node.v8js_memory_heap_used"] != 3145728 {
		t.Fatalf("heap sum = %v, want 3145728", got["svc.node.v8js_memory_heap_used"])
	}
	if v := got["svc.node.v8js_gc_duration_ms"]; v < 4.9 || v > 5.1 {
		t.Fatalf("gc mean ms = %v, want ~5 (0.02/4*1000)", v)
	}
}

func strptr(s string) *string { return &s }
