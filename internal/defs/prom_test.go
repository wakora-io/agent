package defs

import (
	"testing"

	"wakora.io/agent/internal/protocol"
)

func TestApplyPromParsesLabelsAndValues(t *testing.T) {
	body := []byte(`# HELP kafka_topic_partitions Number of partitions
# TYPE kafka_topic_partitions gauge
kafka_topic_partitions{topic="orders"} 6
kafka_topic_partitions{topic="events"} 12
kafka_consumergroup_lag{consumergroup="workers",topic="orders"} 137
process_cpu_seconds_total 42.5
`)
	var o Outcome
	applyProm(&o, []protocol.PromRule{
		{Name: "svc.kafka.partitions", Metric: "kafka_topic_partitions", Tags: []string{"topic"}},
		{Name: "svc.kafka.consumer_lag", Metric: "kafka_consumergroup_lag", Tags: []string{"consumergroup", "topic"}},
		{Name: "svc.kafka.cpu_seconds", Metric: "process_cpu_seconds_total"},
	}, body)

	if len(o.Metrics) != 4 {
		t.Fatalf("expected 4 metrics, got %d: %+v", len(o.Metrics), o.Metrics)
	}
	var lag, cpu *protocol.MetricPoint
	part := 0
	for i := range o.Metrics {
		switch o.Metrics[i].Name {
		case "svc.kafka.consumer_lag":
			lag = &o.Metrics[i]
		case "svc.kafka.cpu_seconds":
			cpu = &o.Metrics[i]
		case "svc.kafka.partitions":
			part++
		}
	}
	if part != 2 {
		t.Fatalf("expected 2 partition series, got %d", part)
	}
	if lag == nil || lag.Value != 137 || lag.Tags["consumergroup"] != "workers" || lag.Tags["topic"] != "orders" {
		t.Fatalf("lag series wrong: %+v", lag)
	}
	if cpu == nil || cpu.Value != 42.5 || len(cpu.Tags) != 0 {
		t.Fatalf("cpu series wrong: %+v", cpu)
	}
}

func TestApplyPromIgnoresCommentsAndUnknown(t *testing.T) {
	body := []byte("# a comment\nother_metric 5\n")
	var o Outcome
	applyProm(&o, []protocol.PromRule{{Name: "svc.x", Metric: "wanted"}}, body)
	if len(o.Metrics) != 0 {
		t.Fatalf("expected no metrics, got %+v", o.Metrics)
	}
}
