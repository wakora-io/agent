package defs

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
)

const trapEventCap = 100

var trapNames = map[string]string{
	"1.3.6.1.6.3.1.1.5.1": "coldStart",
	"1.3.6.1.6.3.1.1.5.2": "warmStart",
	"1.3.6.1.6.3.1.1.5.3": "linkDown",
	"1.3.6.1.6.3.1.1.5.4": "linkUp",
	"1.3.6.1.6.3.1.1.5.5": "authenticationFailure",
}

type TrapEvent struct {
	Source string
	OID    string
	Name   string
	Vars   string
	At     time.Time
}

type V3Auth struct {
	User      string
	AuthProto string
	PrivProto string
	AuthPass  string
	PrivPass  string
}

type TrapListener struct {
	port int
	v3   *V3Auth

	mu      sync.Mutex
	events  []TrapEvent
	total   uint64
	dropped uint64
	allow   map[string]bool
	lastErr error

	tl *gosnmp.TrapListener
}

func NewTrapListener(port int) *TrapListener {
	if port <= 0 {
		port = 162
	}
	return &TrapListener{port: port, allow: map[string]bool{}}
}

func (t *TrapListener) Port() int { return t.port }

func (t *TrapListener) SetV3(a V3Auth) { t.v3 = &a }

func (t *TrapListener) Start() {
	tl := gosnmp.NewTrapListener()
	if t.v3 != nil {
		params, err := v3ListenerParams(*t.v3)
		if err != nil {
			t.mu.Lock()
			t.lastErr = err
			t.mu.Unlock()
			return
		}
		tl.Params = params
	} else {
		tl.Params = gosnmp.Default
	}
	tl.OnNewTrap = func(packet *gosnmp.SnmpPacket, addr *net.UDPAddr) {
		t.ingest(addr.IP.String(), packet)
	}
	t.tl = tl
	go func() {
		err := tl.Listen(fmt.Sprintf("0.0.0.0:%d", t.port))
		t.mu.Lock()
		t.lastErr = err
		t.mu.Unlock()
	}()
}

func v3ListenerParams(a V3Auth) (*gosnmp.GoSNMP, error) {
	g := &gosnmp.GoSNMP{
		Version:       gosnmp.Version3,
		SecurityModel: gosnmp.UserSecurityModel,
		MsgFlags:      gosnmp.NoAuthNoPriv,
		Logger:        gosnmp.NewLogger(nil),
	}
	usm := &gosnmp.UsmSecurityParameters{
		UserName:                 a.User,
		AuthoritativeEngineID:    "wakora-collector",
		AuthoritativeEngineBoots: 1,
		AuthoritativeEngineTime:  uint32(time.Now().Unix()),
	}
	if a.AuthProto != "" {
		proto, ok := snmpAuthProtos[strings.ToUpper(a.AuthProto)]
		if !ok {
			return nil, fmt.Errorf("traps v3: unknown authProto %s", a.AuthProto)
		}
		usm.AuthenticationProtocol = proto
		usm.AuthenticationPassphrase = a.AuthPass
		g.MsgFlags = gosnmp.AuthNoPriv
	}
	if a.PrivProto != "" {
		proto, ok := snmpPrivProtos[strings.ToUpper(a.PrivProto)]
		if !ok {
			return nil, fmt.Errorf("traps v3: unknown privProto %s", a.PrivProto)
		}
		usm.PrivacyProtocol = proto
		usm.PrivacyPassphrase = a.PrivPass
		g.MsgFlags = gosnmp.AuthPriv
	}
	g.SecurityParameters = usm
	return g, nil
}

func (t *TrapListener) Close() {
	if t.tl != nil {
		t.tl.Close()
	}
}

func (t *TrapListener) SetAllowed(ips []string) {
	allow := make(map[string]bool, len(ips))
	for _, ip := range ips {
		if ip != "" {
			allow[ip] = true
		}
	}
	t.mu.Lock()
	t.allow = allow
	t.mu.Unlock()
}

func (t *TrapListener) ingest(source string, packet *gosnmp.SnmpPacket) {
	oid, vars := summarizeTrap(packet)
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.allow[source] {
		t.dropped++
		return
	}
	t.total++
	if len(t.events) >= trapEventCap {
		t.events = t.events[1:]
	}
	t.events = append(t.events, TrapEvent{
		Source: source, OID: oid, Name: trapName(oid), Vars: vars, At: time.Now(),
	})
}

func (t *TrapListener) Drain() (events []TrapEvent, total, dropped uint64, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	events = t.events
	t.events = nil
	return events, t.total, t.dropped, t.lastErr
}

func trapName(oid string) string {
	if n := trapNames[strings.TrimPrefix(oid, ".")]; n != "" {
		return n
	}
	return "trap"
}

func summarizeTrap(packet *gosnmp.SnmpPacket) (trapOID, vars string) {
	if packet == nil {
		return "", ""
	}
	var parts []string
	for _, v := range packet.Variables {
		name := strings.TrimPrefix(v.Name, ".")
		if name == "1.3.6.1.6.3.1.1.4.1.0" {
			trapOID = strings.TrimPrefix(pduString(v), ".")
			continue
		}
		if name == "1.3.6.1.2.1.1.3.0" {
			continue
		}
		if len(parts) < 5 {
			parts = append(parts, name+"="+pduString(v))
		}
	}
	if trapOID == "" && packet.Version == gosnmp.Version1 {
		trapOID = strings.TrimPrefix(packet.Enterprise, ".")
	}
	return trapOID, strings.Join(parts, "; ")
}
