package defs

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
)

const (
	trapEventCap         = 100
	trapPacketMax        = 65535
	usmUnknownEngineIDs  = ".1.3.6.1.6.3.15.1.1.4.0"
	trapReadErrorBackoff = 100 * time.Millisecond
)

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

	conn          *net.UDPConn
	unknownEngine uint32
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
	params := gosnmp.Default
	if t.v3 != nil {
		p, err := v3ListenerParams(*t.v3)
		if err != nil {
			t.setErr(err)
			return
		}
		params = p
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: t.port})
	if err != nil {
		t.setErr(err)
		return
	}
	t.mu.Lock()
	t.conn = conn
	t.mu.Unlock()
	go t.serve(conn, params)
}

func (t *TrapListener) setErr(err error) {
	t.mu.Lock()
	t.lastErr = err
	t.mu.Unlock()
}

func (t *TrapListener) serve(conn *net.UDPConn, params *gosnmp.GoSNMP) {
	buf := make([]byte, trapPacketMax)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			t.setErr(err)
			time.Sleep(trapReadErrorBackoff)
			continue
		}
		source := addr.IP.String()
		if !t.admits(source) {
			continue
		}
		t.handle(conn, params, append([]byte(nil), buf[:n]...), addr, source)
	}
}

func (t *TrapListener) admits(source string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.allow[source] {
		t.dropped++
		return false
	}
	return true
}

func (t *TrapListener) handle(conn *net.UDPConn, params *gosnmp.GoSNMP, msg []byte, addr *net.UDPAddr, source string) {
	defer recoverListener("trap", t.port)
	packet, err := params.UnmarshalTrap(msg, false)
	if err != nil {
		return
	}
	if t.unknownEngineReported(conn, params, packet, addr) {
		return
	}
	t.ingest(source, packet)
	if packet.PDUType != gosnmp.InformRequest {
		return
	}
	packet.PDUType = gosnmp.GetResponse
	packet.Error = gosnmp.NoError
	packet.ErrorIndex = 0
	if out, err := packet.MarshalMsg(); err == nil {
		_, _ = conn.WriteToUDP(out, addr)
	}
}

func (t *TrapListener) unknownEngineReported(conn *net.UDPConn, params *gosnmp.GoSNMP, packet *gosnmp.SnmpPacket, addr *net.UDPAddr) bool {
	if packet.Version != gosnmp.Version3 || packet.SecurityModel != gosnmp.UserSecurityModel || params.SecurityModel != gosnmp.UserSecurityModel {
		return false
	}
	own, ok := params.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	if !ok {
		return false
	}
	theirs, ok := packet.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	if !ok {
		return false
	}
	id := theirs.AuthoritativeEngineID
	if id == own.AuthoritativeEngineID || (len(id) >= 5 && len(id) <= 32) {
		return false
	}
	t.mu.Lock()
	t.unknownEngine++
	count := t.unknownEngine
	t.mu.Unlock()
	sp, ok := theirs.Copy().(*gosnmp.UsmSecurityParameters)
	if !ok {
		return true
	}
	sp.AuthoritativeEngineID = own.AuthoritativeEngineID
	packet.PDUType = gosnmp.Report
	packet.MsgFlags &= gosnmp.AuthPriv
	packet.SecurityParameters = sp
	packet.Variables = []gosnmp.SnmpPDU{{Name: usmUnknownEngineIDs, Value: int(count), Type: gosnmp.Integer}}
	if out, err := packet.MarshalMsg(); err == nil {
		_, _ = conn.WriteToUDP(out, addr)
	}
	return true
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
	t.mu.Lock()
	c := t.conn
	t.conn = nil
	t.mu.Unlock()
	if c != nil {
		_ = c.Close()
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
	t.mu.Lock()
	if !t.allow[source] {
		t.dropped++
		t.mu.Unlock()
		return
	}
	t.mu.Unlock()
	oid, vars := summarizeTrap(packet)
	t.mu.Lock()
	defer t.mu.Unlock()
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
