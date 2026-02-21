package agent

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"wakora.io/agent/internal/protocol"
)

const (
	otlpMaxSpansPerReq = 2000
	otlpMaxAttrs       = 24
	otlpMaxStrLen      = 512
)

type otlpExport struct {
	ResourceSpans []otlpResourceSpans `json:"resourceSpans"`
}

type otlpResourceSpans struct {
	Resource   otlpResource     `json:"resource"`
	ScopeSpans []otlpScopeSpans `json:"scopeSpans"`
}

type otlpResource struct {
	Attributes []otlpKV `json:"attributes"`
}

type otlpScopeSpans struct {
	Spans []otlpSpan `json:"spans"`
}

type otlpSpan struct {
	TraceID           string          `json:"traceId"`
	SpanID            string          `json:"spanId"`
	ParentSpanID      string          `json:"parentSpanId"`
	Name              string          `json:"name"`
	Kind              json.RawMessage `json:"kind"`
	StartTimeUnixNano json.RawMessage `json:"startTimeUnixNano"`
	EndTimeUnixNano   json.RawMessage `json:"endTimeUnixNano"`
	Attributes        []otlpKV        `json:"attributes"`
	Status            otlpStatus      `json:"status"`
}

type otlpStatus struct {
	Code json.RawMessage `json:"code"`
}

type otlpKV struct {
	Key   string  `json:"key"`
	Value otlpAny `json:"value"`
}

type otlpAny struct {
	StringValue *string         `json:"stringValue"`
	IntValue    json.RawMessage `json:"intValue"`
	DoubleValue *float64        `json:"doubleValue"`
	BoolValue   *bool           `json:"boolValue"`
}

func (a *Agent) serveOTLP(ctx context.Context, port int) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/traces", a.handleOTLPTraces)
	srv := &http.Server{Handler: mux, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		log.Printf("otlp: cannot listen on 127.0.0.1:%d: %v", port, err)
		return
	}
	log.Printf("otlp: accepting spans on http://127.0.0.1:%d/v1/traces (loopback, JSON)", port)
	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sc)
	}()
	_ = srv.Serve(ln)
}

func (a *Agent) handleOTLPTraces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.Contains(ct, "json") {
		http.Error(w, "only OTLP/HTTP JSON is accepted (set otel.exporter.otlp.protocol=http/json)", http.StatusUnsupportedMediaType)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	var exp otlpExport
	if err := json.Unmarshal(body, &exp); err != nil {
		http.Error(w, "invalid OTLP JSON", http.StatusBadRequest)
		return
	}
	spans := convertOTLP(exp)
	if len(spans) == 0 {
		w.WriteHeader(http.StatusOK)
		return
	}
	select {
	case a.spans <- spans:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}"))
	default:
		http.Error(w, "agent busy or offline, retry later", http.StatusTooManyRequests)
	}
}

func convertOTLP(exp otlpExport) []protocol.Span {
	var out []protocol.Span
	for _, rs := range exp.ResourceSpans {
		service := ""
		for _, kv := range rs.Resource.Attributes {
			if kv.Key == "service.name" {
				service = anyToString(kv.Value)
				break
			}
		}
		for _, ss := range rs.ScopeSpans {
			for _, sp := range ss.Spans {
				if len(out) >= otlpMaxSpansPerReq {
					return out
				}
				start := rawToUint(sp.StartTimeUnixNano)
				end := rawToUint(sp.EndTimeUnixNano)
				dur := uint64(0)
				if end > start {
					dur = end - start
				}
				out = append(out, protocol.Span{
					TraceID:      sp.TraceID,
					SpanID:       sp.SpanID,
					ParentID:     sp.ParentSpanID,
					Service:      trim(service),
					Name:         trim(sp.Name),
					Kind:         spanKind(sp.Kind),
					StartNano:    start,
					DurationNano: dur,
					Status:       spanStatus(sp.Status.Code),
					Attrs:        convertAttrs(sp.Attributes),
				})
			}
		}
	}
	return out
}

func convertAttrs(kvs []otlpKV) map[string]string {
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
		out[trim(kv.Key)] = trim(anyToString(kv.Value))
	}
	return out
}

func anyToString(v otlpAny) string {
	switch {
	case v.StringValue != nil:
		return *v.StringValue
	case len(v.IntValue) > 0:
		return strings.Trim(string(v.IntValue), `"`)
	case v.DoubleValue != nil:
		return strconv.FormatFloat(*v.DoubleValue, 'g', -1, 64)
	case v.BoolValue != nil:
		return strconv.FormatBool(*v.BoolValue)
	}
	return ""
}

func rawToUint(raw json.RawMessage) uint64 {
	s := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	if s == "" {
		return 0
	}
	n, _ := strconv.ParseUint(s, 10, 64)
	return n
}

func spanKind(raw json.RawMessage) string {
	s := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	switch s {
	case "1", "SPAN_KIND_INTERNAL":
		return "internal"
	case "2", "SPAN_KIND_SERVER":
		return "server"
	case "3", "SPAN_KIND_CLIENT":
		return "client"
	case "4", "SPAN_KIND_PRODUCER":
		return "producer"
	case "5", "SPAN_KIND_CONSUMER":
		return "consumer"
	default:
		return ""
	}
}

func spanStatus(raw json.RawMessage) string {
	s := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	switch s {
	case "2", "STATUS_CODE_ERROR":
		return "error"
	case "1", "STATUS_CODE_OK":
		return "ok"
	default:
		return ""
	}
}

func trim(s string) string {
	if len(s) > otlpMaxStrLen {
		return s[:otlpMaxStrLen]
	}
	return s
}
