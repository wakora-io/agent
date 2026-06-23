package agent

import (
	"encoding/json"
	"strconv"
	"strings"

	"wakora.io/agent/internal/protocol"
)

const (
	otlpMaxMetricSeries = 40
)

type otlpMetricsExport struct {
	ResourceMetrics []otlpResourceMetrics `json:"resourceMetrics"`
}

type otlpResourceMetrics struct {
	Resource     otlpResource       `json:"resource"`
	ScopeMetrics []otlpScopeMetrics `json:"scopeMetrics"`
}

type otlpScopeMetrics struct {
	Metrics []otlpMetric `json:"metrics"`
}

type otlpMetric struct {
	Name      string          `json:"name"`
	Unit      string          `json:"unit"`
	Gauge     *otlpMetricData `json:"gauge"`
	Sum       *otlpMetricData `json:"sum"`
	Histogram *otlpMetricData `json:"histogram"`
}

type otlpMetricData struct {
	DataPoints []otlpNumberDP `json:"dataPoints"`
}

type otlpNumberDP struct {
	AsDouble *float64        `json:"asDouble"`
	AsInt    json.RawMessage `json:"asInt"`
	Sum      *float64        `json:"sum"`
	Count    json.RawMessage `json:"count"`
	Attrs    []otlpKV        `json:"attributes"`
}

func nodeMetricName(name, unit string) (string, float64, bool) {
	if !strings.HasPrefix(name, "nodejs.") && !strings.HasPrefix(name, "v8js.") {
		return "", 0, false
	}
	clean := "svc.node." + strings.ReplaceAll(name, ".", "_")
	scale := 1.0
	if unit == "s" {
		scale = 1000
		clean += "_ms"
	}
	return clean, scale, true
}

func convertOTLPMetrics(exp otlpMetricsExport) []protocol.MetricPoint {
	var out []protocol.MetricPoint
	for _, rm := range exp.ResourceMetrics {
		unit := ""
		for _, kv := range rm.Resource.Attributes {
			if kv.Key == "service.name" {
				unit = anyToString(kv.Value)
				break
			}
		}
		if unit == "" {
			continue
		}
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				if len(out) >= otlpMaxMetricSeries {
					return out
				}
				name, scale, ok := nodeMetricName(m.Name, m.Unit)
				if !ok {
					continue
				}
				v, ok := foldMetricJSON(m)
				if !ok {
					continue
				}
				out = append(out, protocol.MetricPoint{
					Name: name, Value: v * scale, Tags: map[string]string{"unit": trim(unit)},
				})
			}
		}
	}
	return out
}

func foldMetricJSON(m otlpMetric) (float64, bool) {
	switch {
	case m.Gauge != nil:
		v, ok := 0.0, false
		for _, dp := range m.Gauge.DataPoints {
			if x, has := numberDP(dp); has && (!ok || x > v) {
				v, ok = x, true
			}
		}
		return v, ok
	case m.Sum != nil:
		v, ok := 0.0, false
		for _, dp := range m.Sum.DataPoints {
			if x, has := numberDP(dp); has {
				v, ok = v+x, true
			}
		}
		return v, ok
	case m.Histogram != nil:
		var sum float64
		var count uint64
		for _, dp := range m.Histogram.DataPoints {
			if dp.Sum != nil {
				sum += *dp.Sum
			}
			count += rawToUint(dp.Count)
		}
		if count == 0 {
			return 0, false
		}
		return sum / float64(count), true
	}
	return 0, false
}

func numberDP(dp otlpNumberDP) (float64, bool) {
	if dp.AsDouble != nil {
		return *dp.AsDouble, true
	}
	if len(dp.AsInt) > 0 {
		if n, err := strconv.ParseInt(strings.Trim(string(dp.AsInt), `"`), 10, 64); err == nil {
			return float64(n), true
		}
	}
	return 0, false
}
