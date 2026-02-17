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
	TypeEvent     MessageType = "event"
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
	Roles       map[string]string  `json:"roles,omitempty"`
}

type Match struct {
	Process       string `json:"process,omitempty"`
	ProcessPrefix string `json:"processPrefix,omitempty"`
	Port          string `json:"port,omitempty"`
	Package       string `json:"package,omitempty"`
	Unit          string `json:"unit,omitempty"`
	Init          string `json:"init,omitempty"`
}

type ParseRule struct {
	Name  string `json:"name"`
	Regex string `json:"regex"`
	All   bool   `json:"all,omitempty"`
	Count bool   `json:"count,omitempty"`
}

type KVMetric struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

type Counter struct {
	Name  string `json:"name"`
	Regex string `json:"regex,omitempty"`
}

type OID struct {
	Name string `json:"name"`
	OID  string `json:"oid"`
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
	Driver       string      `json:"driver,omitempty"`
	Secret       string      `json:"secret,omitempty"`
	User         string      `json:"user,omitempty"`
	Socket       bool        `json:"socket,omitempty"`
	PortProcess  string      `json:"portProcess,omitempty"`
	Query        string      `json:"query,omitempty"`
	KVMetrics    []KVMetric  `json:"kvMetrics,omitempty"`
	Path         string      `json:"path,omitempty"`
	PathFrom     string      `json:"pathFrom,omitempty"`
	Hash         bool        `json:"hash,omitempty"`
	Counters     []Counter   `json:"counters,omitempty"`
	Target       string      `json:"target,omitempty"`
	Get          []OID       `json:"get,omitempty"`
	Walk         []OID       `json:"walk,omitempty"`
	LabelOID     string      `json:"labelOid,omitempty"`
	DeviceFacts  []OID       `json:"deviceFacts,omitempty"`
	Port         int         `json:"port,omitempty"`
	AllowFrom    []string    `json:"allowFrom,omitempty"`
	OKCodes      []int       `json:"okCodes,omitempty"`
	V3           bool        `json:"v3,omitempty"`
	AuthProto    string      `json:"authProto,omitempty"`
	PrivProto    string      `json:"privProto,omitempty"`
	Context      string      `json:"context,omitempty"`
	Process      string      `json:"process,omitempty"`
	Domains      []string    `json:"domains,omitempty"`
	Channels     []string    `json:"channels,omitempty"`
	WindowSec    int         `json:"windowSec,omitempty"`
	Idents       []string    `json:"idents,omitempty"`
}

type Definition struct {
	Service     string   `json:"service"`
	Match       Match    `json:"match"`
	Hosts       []string `json:"hosts,omitempty"`
	Probes      []Probe  `json:"probes"`
	IntervalSec int      `json:"intervalSec,omitempty"`
}

type AgentEvent struct {
	ServerID  string `json:"serverId"`
	Hostname  string `json:"hostname,omitempty"`
	Kind      string `json:"kind"`
	Detail    string `json:"detail,omitempty"`
	Timestamp int64  `json:"ts"`
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
