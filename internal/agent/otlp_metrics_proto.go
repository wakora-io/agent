package agent

import (
	colmetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	"google.golang.org/protobuf/proto"

	"wakora.io/agent/internal/protocol"
)

func convertOTLPMetricsProto(body []byte) ([]protocol.MetricPoint, error) {
	var req colmetrics.ExportMetricsServiceRequest
	if err := proto.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	var out []protocol.MetricPoint
	for _, rm := range req.ResourceMetrics {
		unit := ""
		if rm.Resource != nil {
			for _, kv := range rm.Resource.Attributes {
				if kv.Key == "service.name" {
					unit = anyPbString(kv.Value)
					break
				}
			}
		}
		if unit == "" {
			continue
		}
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				if len(out) >= otlpMaxMetricSeries {
					return out, nil
				}
				name, scale, ok := nodeMetricName(m.Name, m.Unit)
				if !ok {
					continue
				}
				v, ok := foldMetricPb(m)
				if !ok {
					continue
				}
				out = append(out, protocol.MetricPoint{
					Name: name, Value: v * scale, Tags: map[string]string{"unit": trim(unit)},
				})
			}
		}
	}
	return out, nil
}

func foldMetricPb(m *metricspb.Metric) (float64, bool) {
	switch d := m.Data.(type) {
	case *metricspb.Metric_Gauge:
		v, ok := 0.0, false
		for _, dp := range d.Gauge.DataPoints {
			if x, has := numberDPpb(dp); has && (!ok || x > v) {
				v, ok = x, true
			}
		}
		return v, ok
	case *metricspb.Metric_Sum:
		v, ok := 0.0, false
		for _, dp := range d.Sum.DataPoints {
			if x, has := numberDPpb(dp); has {
				v, ok = v+x, true
			}
		}
		return v, ok
	case *metricspb.Metric_Histogram:
		var sum float64
		var count uint64
		for _, dp := range d.Histogram.DataPoints {
			if dp.Sum != nil {
				sum += *dp.Sum
			}
			count += dp.Count
		}
		if count == 0 {
			return 0, false
		}
		return sum / float64(count), true
	}
	return 0, false
}

func numberDPpb(dp *metricspb.NumberDataPoint) (float64, bool) {
	switch v := dp.Value.(type) {
	case *metricspb.NumberDataPoint_AsDouble:
		return v.AsDouble, true
	case *metricspb.NumberDataPoint_AsInt:
		return float64(v.AsInt), true
	}
	return 0, false
}

func otlpMetricsProtoResponse() []byte {
	b, _ := proto.Marshal(&colmetrics.ExportMetricsServiceResponse{})
	return b
}
