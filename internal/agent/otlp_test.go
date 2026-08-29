package agent

import (
	"encoding/json"
	"testing"

	"wakora.io/agent/internal/protocol"
)

func TestDropNoiseSpans(t *testing.T) {
	in := []protocol.Span{
		{Name: "mysqli_query", SpanID: "a"},
		{Name: "mysqli_next_result", SpanID: "b"},
		{Name: "mysqli_next_result", SpanID: "c"},
		{Name: "GET /", SpanID: "d"},
	}
	out := dropNoiseSpans(in)
	if len(out) != 2 {
		t.Fatalf("want 2 spans, got %d", len(out))
	}
	if out[0].SpanID != "a" || out[1].SpanID != "d" {
		t.Fatalf("wrong survivors: %+v", out)
	}
}

func TestConvertOTLPMergesResourceAttrs(t *testing.T) {
	raw := `{"resourceSpans":[{"resource":{"attributes":[
		{"key":"service.name","value":{"stringValue":"shop"}},
		{"key":"php.version","value":{"stringValue":"8.1.34"}},
		{"key":"php.sapi","value":{"stringValue":"fpm-fcgi"}},
		{"key":"process.runtime.name","value":{"stringValue":"fpm-fcgi"}},
		{"key":"host.name","value":{"stringValue":"box"}},
		{"key":"os.type","value":{"stringValue":"linux"}},
		{"key":"telemetry.sdk.name","value":{"stringValue":"opentelemetry"}},
		{"key":"service.instance.id","value":{"stringValue":"abc"}}
	]},"scopeSpans":[{"spans":[
		{"traceId":"t1","spanId":"s1","name":"GET /","kind":2,
		 "startTimeUnixNano":"100","endTimeUnixNano":"200",
		 "attributes":[{"key":"php.version","value":{"stringValue":"span-wins"}}],
		 "status":{}}
	]}]}]}`
	var exp otlpExport
	if err := json.Unmarshal([]byte(raw), &exp); err != nil {
		t.Fatal(err)
	}
	spans := convertOTLP(exp)
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	a := spans[0].Attrs
	if a["php.version"] != "span-wins" {
		t.Fatalf("span attr must win over resource attr, got %q", a["php.version"])
	}
	if a["php.sapi"] != "fpm-fcgi" {
		t.Fatalf("resource attr not merged: %v", a)
	}
	if a["process.runtime.name"] != "fpm-fcgi" {
		t.Fatalf("allow-listed runtime attr not merged: %v", a)
	}
	for _, dropped := range []string{"telemetry.sdk.name", "service.instance.id", "host.name", "os.type"} {
		if _, ok := a[dropped]; ok {
			t.Fatalf("resource attr %s must be dropped", dropped)
		}
	}
	if spans[0].Service != "shop" {
		t.Fatalf("service mapping broken: %q", spans[0].Service)
	}
}
