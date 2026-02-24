package agent

import (
	"encoding/hex"
	"strconv"

	coltrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"

	"wakora.io/agent/internal/protocol"
)

func convertOTLPProto(body []byte) ([]protocol.Span, error) {
	var req coltrace.ExportTraceServiceRequest
	if err := proto.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	var out []protocol.Span
	for _, rs := range req.ResourceSpans {
		service := ""
		res := make(map[string]string, otlpMaxResAttrs)
		if rs.Resource != nil {
			for _, kv := range rs.Resource.Attributes {
				if kv.Key == "service.name" {
					service = anyPbString(kv.Value)
					continue
				}
				if keepResourceAttr(kv.Key) && len(res) < otlpMaxResAttrs {
					res[trim(kv.Key)] = trim(anyPbString(kv.Value))
				}
			}
		}
		for _, ss := range rs.ScopeSpans {
			for _, sp := range ss.Spans {
				if len(out) >= otlpMaxSpansPerReq {
					return out, nil
				}
				dur := uint64(0)
				if sp.EndTimeUnixNano > sp.StartTimeUnixNano {
					dur = sp.EndTimeUnixNano - sp.StartTimeUnixNano
				}
				out = append(out, protocol.Span{
					TraceID:      hex.EncodeToString(sp.TraceId),
					SpanID:       hex.EncodeToString(sp.SpanId),
					ParentID:     hex.EncodeToString(sp.ParentSpanId),
					Service:      trim(service),
					Name:         trim(sp.Name),
					Kind:         spanKindPb(sp.Kind),
					StartNano:    sp.StartTimeUnixNano,
					DurationNano: dur,
					Status:       spanStatusPb(sp.Status),
					Attrs:        mergeResourceAttrs(convertAttrsPb(sp.Attributes), res),
				})
			}
		}
	}
	return out, nil
}

func otlpProtoResponse() []byte {
	b, _ := proto.Marshal(&coltrace.ExportTraceServiceResponse{})
	return b
}

func convertAttrsPb(kvs []*commonpb.KeyValue) map[string]string {
	if len(kvs) == 0 {
		return nil
	}
	out := make(map[string]string, otlpMaxAttrs)
	for _, kv := range kvs {
		if len(out) >= otlpMaxAttrs {
			break
		}
		if kv.Key == "" {
			continue
		}
		out[trim(kv.Key)] = trim(anyPbString(kv.Value))
	}
	return out
}

func anyPbString(v *commonpb.AnyValue) string {
	if v == nil {
		return ""
	}
	switch t := v.Value.(type) {
	case *commonpb.AnyValue_StringValue:
		return t.StringValue
	case *commonpb.AnyValue_IntValue:
		return strconv.FormatInt(t.IntValue, 10)
	case *commonpb.AnyValue_DoubleValue:
		return strconv.FormatFloat(t.DoubleValue, 'g', -1, 64)
	case *commonpb.AnyValue_BoolValue:
		return strconv.FormatBool(t.BoolValue)
	}
	return ""
}

func spanKindPb(k tracepb.Span_SpanKind) string {
	switch k {
	case tracepb.Span_SPAN_KIND_INTERNAL:
		return "internal"
	case tracepb.Span_SPAN_KIND_SERVER:
		return "server"
	case tracepb.Span_SPAN_KIND_CLIENT:
		return "client"
	case tracepb.Span_SPAN_KIND_PRODUCER:
		return "producer"
	case tracepb.Span_SPAN_KIND_CONSUMER:
		return "consumer"
	}
	return ""
}

func spanStatusPb(s *tracepb.Status) string {
	if s == nil {
		return ""
	}
	switch s.Code {
	case tracepb.Status_STATUS_CODE_ERROR:
		return "error"
	case tracepb.Status_STATUS_CODE_OK:
		return "ok"
	}
	return ""
}
