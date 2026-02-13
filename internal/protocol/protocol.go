package protocol

import "encoding/json"

type MessageType string

const (
	TypeHeartbeat MessageType = "heartbeat"
	TypeMetrics   MessageType = "metrics"
	TypeDiscovery MessageType = "discovery"
	TypeConfig    MessageType = "config"
	TypeCommand   MessageType = "command"
	TypeCheck     MessageType = "check"
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
	Hostname  string        `json:"hostname,omitempty"`
	Timestamp int64         `json:"ts"`
	Points    []MetricPoint `json:"points"`
}

type Heartbeat struct {
	ServerID  string `json:"serverId"`
	Hostname  string `json:"hostname,omitempty"`
	Version   string `json:"version,omitempty"`
	Timestamp int64  `json:"ts"`
}

type Command struct {
	Action string `json:"action"`
	Key    string `json:"key,omitempty"`
}

type Fact struct {
	Kind    string `json:"kind"`
	Key     string `json:"key"`
	Payload string `json:"payload,omitempty"`
}

type DiscoverySnapshot struct {
	ServerID  string `json:"serverId"`
	Hostname  string `json:"hostname,omitempty"`
	Timestamp int64  `json:"ts"`
	Facts     []Fact `json:"facts"`
}

type SignedDefinition struct {
	Def json.RawMessage `json:"def"`
	Sig string          `json:"sig"`
}

type DefinitionSet struct {
	Definitions []SignedDefinition `json:"definitions"`
}

type Match struct {
	Process string `json:"process,omitempty"`
	Port    string `json:"port,omitempty"`
	Package string `json:"package,omitempty"`
	Unit    string `json:"unit,omitempty"`
}

type ParseRule struct {
	Name  string `json:"name"`
	Regex string `json:"regex"`
}

type Probe struct {
	Name         string      `json:"name"`
	Type         string      `json:"type"`
	URL          string      `json:"url,omitempty"`
	Address      string      `json:"address,omitempty"`
	ExpectStatus int         `json:"expectStatus,omitempty"`
	TimeoutSec   int         `json:"timeoutSec,omitempty"`
	Command      string      `json:"command,omitempty"`
	Args         []string    `json:"args,omitempty"`
	Metrics      []ParseRule `json:"metrics,omitempty"`
	Facts        []ParseRule `json:"facts,omitempty"`
}

type Definition struct {
	Service     string  `json:"service"`
	Match       Match   `json:"match"`
	Probes      []Probe `json:"probes"`
	IntervalSec int     `json:"intervalSec,omitempty"`
}

type CheckResult struct {
	ServerID  string  `json:"serverId"`
	Hostname  string  `json:"hostname,omitempty"`
	CheckID   string  `json:"checkId"`
	Kind      string  `json:"kind"`
	Target    string  `json:"target,omitempty"`
	Status    string  `json:"status"`
	LatencyMs float64 `json:"latencyMs"`
	Error     string  `json:"error,omitempty"`
	Timestamp int64   `json:"ts"`
}

func Encode(t MessageType, seq uint64, v any) (Message, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return Message{}, err
	}
	return Message{Type: t, Seq: seq, Payload: raw}, nil
}
