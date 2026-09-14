package agent

import (
	"encoding/json"
	"strings"
	"testing"

	coltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"

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

func TestConvertOTLPRedactsQueryValuesOnBothWireFormats(t *testing.T) {
	const secret = "PLACEHOLDER_SECRET"
	const full = "https://api.example.com/v1/items?key=" + secret + "&page=2"

	raw := `{"resourceSpans":[{"resource":{"attributes":[
		{"key":"service.name","value":{"stringValue":"shop"}}
	]},"scopeSpans":[{"spans":[
		{"traceId":"t1","spanId":"s1","name":"GET","kind":3,
		 "startTimeUnixNano":"100","endTimeUnixNano":"200",
		 "attributes":[
			{"key":"url.full","value":{"stringValue":"` + full + `"}},
			{"key":"url.path","value":{"stringValue":"/v1/items"}}
		 ],
		 "status":{}}
	]}]}]}`
	var exp otlpExport
	if err := json.Unmarshal([]byte(raw), &exp); err != nil {
		t.Fatal(err)
	}
	jsonSpans := convertOTLP(exp)
	if len(jsonSpans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(jsonSpans))
	}

	body, err := proto.Marshal(&coltrace.ExportTraceServiceRequest{
		ResourceSpans: []*tracepb.ResourceSpans{{
			Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{{
				Key:   "service.name",
				Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "shop"}},
			}}},
			ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{{
				TraceId: []byte{1}, SpanId: []byte{2}, Name: "GET",
				StartTimeUnixNano: 100, EndTimeUnixNano: 200,
				Attributes: []*commonpb.KeyValue{
					{Key: "url.full", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: full}}},
					{Key: "url.path", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "/v1/items"}}},
				},
			}}}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	protoSpans, err := convertOTLPProto(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(protoSpans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(protoSpans))
	}

	for name, spans := range map[string][]protocol.Span{"json": jsonSpans, "protobuf": protoSpans} {
		a := spans[0].Attrs
		if strings.Contains(a["url.full"], secret) {
			t.Fatalf("%s wire format leaked a query value: %q", name, a["url.full"])
		}
		if a["url.full"] != "https://api.example.com/v1/items?key=***&page=***" {
			t.Fatalf("%s wire format lost the url shape: %q", name, a["url.full"])
		}
		if a["url.path"] != "/v1/items" {
			t.Fatalf("%s wire format altered a plain path: %q", name, a["url.path"])
		}
	}
}
