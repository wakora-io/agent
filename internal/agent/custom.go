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
	customMaxTags     = 8
	customMaxNameLen  = 120
	customMaxValueLen = 64
)

type customMetric struct {
	Name  string            `json:"name"`
	Value float64           `json:"value"`
	Tags  map[string]string `json:"tags,omitempty"`
}

func (a *Agent) serveCustomMetrics(ctx context.Context, port int) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ingest", a.handleCustomIngest)
	srv := &http.Server{
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		log.Printf("custom metrics: cannot listen on 127.0.0.1:%d: %v", port, err)
		return
	}
	log.Printf("custom metrics: accepting app KPIs on http://127.0.0.1:%d/ingest (app.* only, loopback)", port)
	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sc)
	}()
	_ = srv.Serve(ln)
}

func (a *Agent) handleCustomIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	var single customMetric
	var batch []customMetric
	if json.Unmarshal(body, &batch) != nil {
		if json.Unmarshal(body, &single) != nil {
			http.Error(w, "want {name,value,tags} or an array of them", http.StatusBadRequest)
			return
		}
		batch = []customMetric{single}
	}

	pts := make([]protocol.MetricPoint, 0, len(batch))
	for _, m := range batch {
		if pt, ok := sanitizeCustom(m); ok {
			pts = append(pts, pt)
		}
	}
	if len(pts) == 0 {
		http.Error(w, "no valid metrics (names must start with app.)", http.StatusBadRequest)
		return
	}
	select {
	case a.custom <- pts:
		w.WriteHeader(http.StatusAccepted)
	default:
		http.Error(w, "agent busy or offline, retry later", http.StatusTooManyRequests)
	}
}

func sanitizeCustom(m customMetric) (protocol.MetricPoint, bool) {
	if !strings.HasPrefix(m.Name, "app.") || len(m.Name) > customMaxNameLen {
		return protocol.MetricPoint{}, false
	}
	var tags map[string]string
	if len(m.Tags) > 0 {
		tags = make(map[string]string, customMaxTags)
		n := 0
		for k, v := range m.Tags {
			if n >= customMaxTags {
				break
			}
			if len(k) > customMaxValueLen {
				k = k[:customMaxValueLen]
			}
			if len(v) > customMaxValueLen {
				v = v[:customMaxValueLen]
			}
			tags[k] = v
			n++
		}
	}
	return protocol.MetricPoint{Name: m.Name, Value: m.Value, Tags: tags}, true
}
