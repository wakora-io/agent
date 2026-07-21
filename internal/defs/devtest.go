package defs

import (
	"time"

	"github.com/gosnmp/gosnmp"

	"wakora.io/agent/internal/protocol"
	"wakora.io/agent/internal/secret"
)

func DeviceTest(t protocol.DevTest, resolve func(string) (secret.Cred, bool)) protocol.DevTestResult {
	out := protocol.DevTestResult{Nonce: t.Nonce}
	var cred secret.Cred
	community := "public"
	if t.Secret != "" {
		c, ok := resolve(t.Secret)
		if !ok {
			out.Error = "secret " + t.Secret + " is not set on this collector (wakora secret set " + t.Secret + ")"
			return out
		}
		cred = c
		if c.Pass != "" {
			community = c.Pass
		}
	}
	port := uint16(161)
	if t.Port > 0 && t.Port < 65536 {
		port = uint16(t.Port)
	}
	g := &gosnmp.GoSNMP{Target: t.Target, Port: port, Timeout: 2 * time.Second, Retries: 0, MaxOids: 2}
	if t.V3 {
		p := protocol.Probe{V3: true, AuthProto: t.AuthProto, PrivProto: t.PrivProto, Context: t.Context}
		if err := snmpV3(g, p, cred); err != nil {
			out.Error = err.Error()
			return out
		}
	} else {
		g.Version = gosnmp.Version2c
		g.Community = community
	}
	if err := g.Connect(); err != nil {
		out.Error = "connect: " + err.Error()
		return out
	}
	defer g.Conn.Close()
	res, err := g.Get([]string{".1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.1.2.0"})
	if err != nil {
		out.Error = "the device did not answer - unreachable, powered off, wrong port or wrong credential"
		return out
	}
	if len(res.Variables) < 2 {
		out.Error = "the device answered without sys facts"
		return out
	}
	for _, pdu := range res.Variables {
		switch pdu.Type {
		case gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.EndOfMibView, gosnmp.Null:
			out.Error = "the device answered without sys facts"
			return out
		}
	}
	out.OK = true
	out.SysDescr = pduString(res.Variables[0])
	out.SysObjectID = pduString(res.Variables[1])
	return out
}
