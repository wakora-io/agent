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
	TypeChecks    MessageType = "checks"
	TypeEvent     MessageType = "event"
	TypeSpans     MessageType = "spans"
	TypeProfile   MessageType = "profile"
	TypeRum       MessageType = "rum"
	TypeLogs      MessageType = "logs"
	TypeFlows     MessageType = "flows"
	TypeDevConfig MessageType = "devconfig"
	TypeDevTest   MessageType = "devtest"
	TypeAck       MessageType = "ack"
)

type DevTest struct {
	Nonce     string `json:"nonce"`
	Target    string `json:"target"`
	Port      int    `json:"port"`
	Secret    string `json:"secret"`
	V3        bool   `json:"v3,omitempty"`
	AuthProto string `json:"authProto,omitempty"`
	PrivProto string `json:"privProto,omitempty"`
	Context   string `json:"context,omitempty"`
}

type DevTestResult struct {
	Nonce       string `json:"nonce"`
	OK          bool   `json:"ok"`
	Error       string `json:"error,omitempty"`
	SysDescr    string `json:"sysDescr,omitempty"`
	SysObjectID string `json:"sysObjectId,omitempty"`
}

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
	Pin       string `json:"pin,omitempty"`
	Timestamp int64  `json:"ts"`
}

type Span struct {
	TraceID      string            `json:"traceId"`
	SpanID       string            `json:"spanId"`
	ParentID     string            `json:"parentId,omitempty"`
	Service      string            `json:"service,omitempty"`
	Name         string            `json:"name"`
	Kind         string            `json:"kind,omitempty"`
	StartNano    uint64            `json:"startNano"`
	DurationNano uint64            `json:"durNano"`
	Status       string            `json:"status,omitempty"`
	Attrs        map[string]string `json:"attrs,omitempty"`
}

type SpanBatch struct {
	ServerID string `json:"serverId"`
	Hostname string `json:"hostname,omitempty"`
	Spans    []Span `json:"spans"`
}

type LogLine struct {
	Ts      int64  `json:"ts"`
	Service string `json:"service"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

type LogBatch struct {
	ServerID string    `json:"serverId"`
	Hostname string    `json:"hostname,omitempty"`
	Lines    []LogLine `json:"lines"`
}

type FlowRow struct {
	Src     string `json:"src,omitempty"`
	Dst     string `json:"dst,omitempty"`
	Proto   uint8  `json:"proto,omitempty"`
	DstPort uint16 `json:"dstPort,omitempty"`
	Bytes   uint64 `json:"bytes"`
	Packets uint64 `json:"packets,omitempty"`
}

type FlowBatch struct {
	ServerID    string    `json:"serverId"`
	Hostname    string    `json:"hostname,omitempty"`
	Exporter    string    `json:"exporter"`
	WindowStart int64     `json:"windowStart"`
	WindowSec   int       `json:"windowSec"`
	TotalBytes  uint64    `json:"totalBytes"`
	TotalFlows  uint64    `json:"totalFlows"`
	Rows        []FlowRow `json:"rows"`
}

type DeviceConfig struct {
	ServerID  string `json:"serverId"`
	Hostname  string `json:"hostname,omitempty"`
	Device    string `json:"device"`
	Service   string `json:"service"`
	Sha       string `json:"sha"`
	Config    string `json:"config"`
	FetchedAt int64  `json:"fetchedAt"`
}

type FoldedStack struct {
	Stack   string `json:"stack"`
	Samples uint32 `json:"samples"`
	Pool    string `json:"pool,omitempty"`
}

type ProfileBatch struct {
	ServerID    string        `json:"serverId"`
	Hostname    string        `json:"hostname,omitempty"`
	Service     string        `json:"service"`
	Timestamp   int64         `json:"ts"`
	WindowSec   uint32        `json:"windowSec"`
	SampleRate  uint32        `json:"sampleRate"`
	SampleTotal uint32        `json:"sampleTotal"`
	SampleHits  uint32        `json:"sampleHits"`
	Stacks      []FoldedStack `json:"stacks"`
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
	Def  json.RawMessage `json:"def"`
	Sig  string          `json:"sig"`
	Tier string          `json:"tier,omitempty"`
}

type DefinitionSet struct {
	Definitions  []SignedDefinition `json:"definitions"`
	Roles        map[string]string  `json:"roles,omitempty"`
	Deny         []string           `json:"deny,omitempty"`
	Allow        []string           `json:"allow,omitempty"`
	RumSites     []string           `json:"rumSites,omitempty"`
	DenyServices []string           `json:"denyServices,omitempty"`
	LogDeep      []string           `json:"logDeep,omitempty"`
	Pin          string             `json:"pin,omitempty"`
	TenantKey    string             `json:"tenantKey,omitempty"`
}

type RumError struct {
	Msg string `json:"msg"`
	Src string `json:"src,omitempty"`
	N   uint32 `json:"n,omitempty"`
}

type RumItem struct {
	Site    string             `json:"site"`
	Path    string             `json:"path"`
	Dev     string             `json:"dev,omitempty"`
	Browser string             `json:"browser,omitempty"`
	IP      string             `json:"ip,omitempty"`
	Trace   string             `json:"trace,omitempty"`
	Vitals  map[string]float64 `json:"vitals,omitempty"`
	Errors  []RumError         `json:"errors,omitempty"`
}

type RumBatch struct {
	ServerID string    `json:"serverId"`
	Hostname string    `json:"hostname,omitempty"`
	Items    []RumItem `json:"items"`
}

type Match struct {
	Process       string `json:"process,omitempty"`
	ProcessPrefix string `json:"processPrefix,omitempty"`
	Port          string `json:"port,omitempty"`
	Package       string `json:"package,omitempty"`
	Unit          string `json:"unit,omitempty"`
	Init          string `json:"init,omitempty"`
	Capability    string `json:"capability,omitempty"`
}

type ParseRule struct {
	Name  string `json:"name"`
	Regex string `json:"regex"`
	All   bool   `json:"all,omitempty"`
	Count bool   `json:"count,omitempty"`
}

type PromRule struct {
	Name   string   `json:"name"`
	Metric string   `json:"metric"`
	Tags   []string `json:"tags,omitempty"`
}

type Component struct {
	Name  string `json:"name"`
	Ports []int  `json:"ports"`
}

type KVMetric struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

type KVRatio struct {
	Name  string  `json:"name"`
	Num   string  `json:"num"`
	Den   string  `json:"den"`
	Scale float64 `json:"scale,omitempty"`
}

type Counter struct {
	Name    string `json:"name"`
	Regex   string `json:"regex,omitempty"`
	Capture string `json:"capture,omitempty"`
	Event   string `json:"event,omitempty"`
	Min     int    `json:"min,omitempty"`
}

type RateRule struct {
	Name string `json:"name"`
	Out  string `json:"out,omitempty"`
	Per  string `json:"per,omitempty"`
}

type OIDUnit struct {
	Tag   string  `json:"tag"`
	Scale float64 `json:"scale,omitempty"`
}

type OID struct {
	Name     string             `json:"name"`
	OID      string             `json:"oid"`
	Scale    float64            `json:"scale,omitempty"`
	LabelOID string             `json:"labelOid,omitempty"`
	LabelTag string             `json:"labelTag,omitempty"`
	UnitOID  string             `json:"unitOid,omitempty"`
	Units    map[string]OIDUnit `json:"units,omitempty"`
}

type Probe struct {
	Name         string            `json:"name"`
	Type         string            `json:"type"`
	URL          string            `json:"url,omitempty"`
	URLs         []string          `json:"urls,omitempty"`
	Bearer       bool              `json:"bearer,omitempty"`
	Insecure     bool              `json:"insecure,omitempty"`
	Optional     bool              `json:"optional,omitempty"`
	Address      string            `json:"address,omitempty"`
	ExpectStatus int               `json:"expectStatus,omitempty"`
	TimeoutSec   int               `json:"timeoutSec,omitempty"`
	Command      string            `json:"command,omitempty"`
	Args         []string          `json:"args,omitempty"`
	Metrics      []ParseRule       `json:"metrics,omitempty"`
	Facts        []ParseRule       `json:"facts,omitempty"`
	Driver       string            `json:"driver,omitempty"`
	Secret       string            `json:"secret,omitempty"`
	SecretOpt    string            `json:"secretOptional,omitempty"`
	AuthHeader   string            `json:"authHeader,omitempty"`
	User         string            `json:"user,omitempty"`
	Socket       bool              `json:"socket,omitempty"`
	PortProcess  string            `json:"portProcess,omitempty"`
	PortFrom     string            `json:"portFrom,omitempty"`
	Query        string            `json:"query,omitempty"`
	KVMetrics    []KVMetric        `json:"kvMetrics,omitempty"`
	KVFacts      []KVMetric        `json:"kvFacts,omitempty"`
	KVRatios     []KVRatio         `json:"kvRatios,omitempty"`
	Path         string            `json:"path,omitempty"`
	PathFrom     string            `json:"pathFrom,omitempty"`
	Hash         bool              `json:"hash,omitempty"`
	Age          bool              `json:"age,omitempty"`
	Counters     []Counter         `json:"counters,omitempty"`
	Rates        []RateRule        `json:"rates,omitempty"`
	Target       string            `json:"target,omitempty"`
	Get          []OID             `json:"get,omitempty"`
	Walk         []OID             `json:"walk,omitempty"`
	LabelOID     string            `json:"labelOid,omitempty"`
	DeviceFacts  []OID             `json:"deviceFacts,omitempty"`
	Port         int               `json:"port,omitempty"`
	Ports        []int             `json:"ports,omitempty"`
	Downstream   []Component       `json:"downstream,omitempty"`
	Capability   string            `json:"capability,omitempty"`
	Options      map[string]string `json:"options,omitempty"`
	AllowFrom    []string          `json:"allowFrom,omitempty"`
	OKCodes      []int             `json:"okCodes,omitempty"`
	V3           bool              `json:"v3,omitempty"`
	AuthProto    string            `json:"authProto,omitempty"`
	PrivProto    string            `json:"privProto,omitempty"`
	Context      string            `json:"context,omitempty"`
	Sensors      bool              `json:"sensors,omitempty"`
	PoE          bool              `json:"poe,omitempty"`
	Topology     bool              `json:"topology,omitempty"`
	Process      string            `json:"process,omitempty"`
	Domains      []string          `json:"domains,omitempty"`
	Channels     []string          `json:"channels,omitempty"`
	WindowSec    int               `json:"windowSec,omitempty"`
	Idents       []string          `json:"idents,omitempty"`
	Targets      []string          `json:"targets,omitempty"`
	ExpectBody   string            `json:"expectBody,omitempty"`
	Prom         []PromRule        `json:"prom,omitempty"`
	IntervalSec  int               `json:"intervalSec,omitempty"`
	Paths        []string          `json:"paths,omitempty"`
	LevelRegex   string            `json:"levelRegex,omitempty"`
	MinLevel     string            `json:"minLevel,omitempty"`
	ForceLevel   string            `json:"forceLevel,omitempty"`
	Redact       []string          `json:"redact,omitempty"`
	Docker       bool              `json:"docker,omitempty"`
	K8s          bool              `json:"k8s,omitempty"`
	Normalize    []string          `json:"normalize,omitempty"`
	Mask         []string          `json:"mask,omitempty"`
	Nonce        string            `json:"nonce,omitempty"`
}

type DerivedRule struct {
	Name  string  `json:"name"`
	Num   string  `json:"num"`
	Den   string  `json:"den"`
	Scale float64 `json:"scale,omitempty"`
}

type Definition struct {
	Service         string        `json:"service"`
	Match           Match         `json:"match"`
	Hosts           []string      `json:"hosts,omitempty"`
	RunOn           []string      `json:"runOn,omitempty"`
	Probes          []Probe       `json:"probes"`
	Derived         []DerivedRule `json:"derived,omitempty"`
	IntervalSec     int           `json:"intervalSec,omitempty"`
	MinAgentVersion string        `json:"minAgentVersion,omitempty"`
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

type CheckBatch struct {
	ServerID string        `json:"serverId"`
	Hostname string        `json:"hostname,omitempty"`
	Checks   []CheckResult `json:"checks"`
}

func Encode(t MessageType, seq uint64, v any) (Message, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return Message{}, err
	}
	return Message{Type: t, Seq: seq, Payload: raw}, nil
}
