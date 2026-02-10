package protocol

import "encoding/json"

type MessageType string

const (
	TypeHeartbeat MessageType = "heartbeat"
	TypeMetrics   MessageType = "metrics"
	TypeDiscovery MessageType = "discovery"
	TypeConfig    MessageType = "config"
	TypeCommand   MessageType = "command"
	TypeAck       MessageType = "ack"
)

type Message struct {
	Type    MessageType     `json:"type"`
	Seq     uint64          `json:"seq"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type MetricPoint struct {
	Name  string            `json:"name"`
	Value float64           `json:"value"`
	Tags  map[string]string `json:"tags,omitempty"`
}

type MetricsBatch struct {
	ServerID  string        `json:"serverId"`
	Timestamp int64         `json:"ts"`
	Points    []MetricPoint `json:"points"`
}

func Encode(t MessageType, seq uint64, v any) (Message, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return Message{}, err
	}
	return Message{Type: t, Seq: seq, Payload: raw}, nil
}
