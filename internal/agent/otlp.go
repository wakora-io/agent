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
	otlpMaxResAttrs    = 8
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

func (a *Agent) serveOTLP(ctx context.Context, port int, binds []string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/traces", a.handleOTLPTraces)
	srv := &http.Server{Handler: mux, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}

	hosts := []string{"127.0.0.1"}
	for _, b := range binds {
		if b = strings.TrimSpace(b); b != "" && b != "127.0.0.1" {
			hosts = append(hosts, b)
		}
	}
	bound := 0
	for _, h := range hosts {
		addr := net.JoinHostPort(h, strconv.Itoa(port))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Printf("otlp: cannot listen on %s: %v", addr, err)
			continue
		}
		bound++
		scope := "loopback"
		if h != "127.0.0.1" {
			scope = "container bridge"
		}
		log.Printf("otlp: accepting spans on http://%s/v1/traces (%s, JSON)", addr, scope)
		go func(l net.Listener) { _ = srv.Serve(l) }(ln)
	}
	if bound == 0 {
		return
	}
	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sc)
	}()
	<-ctx.Done()
}

func (a *Agent) handleOTLPTraces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	ct := r.Header.Get("Content-Type")
	proto := strings.Contains(ct, "protobuf") || strings.Contains(ct, "x-protobuf")
	var spans []protocol.Span
	if proto {
		spans, err = convertOTLPProto(body)
		if err != nil {
			http.Error(w, "invalid OTLP protobuf", http.StatusBadRequest)
			return
		}
	} else {
		var exp otlpExport
		if err := json.Unmarshal(body, &exp); err != nil {
			http.Error(w, "invalid OTLP JSON", http.StatusBadRequest)
			return
		}
		spans = convertOTLP(exp)
	}
	if len(spans) == 0 {
		w.WriteHeader(http.StatusOK)
		return
	}
	select {
	case a.spans <- spans:
		if proto {
			w.Header().Set("Content-Type", "application/x-protobuf")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(otlpProtoResponse())
			return
		}
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
		res := make(map[string]string, otlpMaxResAttrs)
		for _, kv := range rs.Resource.Attributes {
			if kv.Key == "service.name" {
				service = anyToString(kv.Value)
				continue
			}
			if keepResourceAttr(kv.Key) && len(res) < otlpMaxResAttrs {
				res[trim(kv.Key)] = trim(anyToString(kv.Value))
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
					Attrs:        mergeResourceAttrs(convertAttrs(sp.Attributes), res),
				})
			}
		}
	}
	return out
}

func keepResourceAttr(key string) bool {
	return key != "" && !strings.HasPrefix(key, "telemetry.") && !strings.HasPrefix(key, "service.instance")
}

func mergeResourceAttrs(attrs, res map[string]string) map[string]string {
	if len(res) == 0 {
		return attrs
	}
	if attrs == nil {
		attrs = make(map[string]string, len(res))
	}
	for k, v := range res {
		if len(attrs) >= otlpMaxAttrs {
			break
		}
		if _, ok := attrs[k]; !ok {
			attrs[k] = v
		}
	}
	return attrs
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
