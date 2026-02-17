package defs

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"

	"wakora.io/agent/internal/protocol"
	"wakora.io/agent/internal/secret"
)

func runSNMP(o *Outcome, service string, p protocol.Probe, timeout time.Duration, resolve CredResolver) {
	o.Check.Target = p.Target
	if p.Target == "" {
		o.Check.Status = "fail"
		o.Check.Error = "snmp target not set"
		return
	}
	var cred secret.Cred
	if p.Secret != "" {
		c, ok := resolve(p.Secret)
		if !ok {
			o.Check.Status = "fail"
			o.Check.Error = "secret " + p.Secret + " not set on host (wakora secret set)"
			return
		}
		cred = c
	}

	host, port := p.Target, uint16(161)
	if h, ps, ok := strings.Cut(p.Target, ":"); ok {
		host = h
		if n, err := strconv.ParseUint(ps, 10, 16); err == nil {
			port = uint16(n)
		}
	}
	g := &gosnmp.GoSNMP{
		Target: host, Port: port,
		Timeout: timeout, Retries: 1, MaxOids: 60,
	}
	if p.V3 {
		if err := snmpV3(g, p, cred); err != nil {
			o.Check.Status = "fail"
			o.Check.Error = err.Error()
			return
		}
	} else {
		g.Version = gosnmp.Version2c
		g.Community = "public"
		if cred.Pass != "" {
			g.Community = cred.Pass
		}
	}
	if err := g.Connect(); err != nil {
		o.Check.Status = "fail"
		o.Check.Error = "connect: " + err.Error()
		return
	}
	defer g.Conn.Close()

	deviceTag := map[string]string{"device": host}
	var lastErr string

	facts := map[string]string{}
	factOIDs := make([]string, 0, len(p.DeviceFacts))
	for _, f := range p.DeviceFacts {
		factOIDs = append(factOIDs, normOID(f.OID))
	}
	if len(factOIDs) > 0 {
		if res, err := g.Get(factOIDs); err == nil {
			for i, pdu := range res.Variables {
				facts[p.DeviceFacts[i].Name] = pduString(pdu)
			}
		} else {
			lastErr = "get facts: " + err.Error()
		}
	}

	var getOIDs []string
	for _, m := range p.Get {
		getOIDs = append(getOIDs, normOID(m.OID))
	}
	if len(getOIDs) > 0 {
		if res, err := g.Get(getOIDs); err == nil {
			for i, pdu := range res.Variables {
				if v, ok := pduNum(pdu); ok {
					o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: p.Get[i].Name, Value: v, Tags: copyTags(deviceTag)})
				}
			}
		} else {
			lastErr = "get: " + err.Error()
		}
	}

	labels := map[string]string{}
	if p.LabelOID != "" {
		base := normOID(p.LabelOID)
		_ = g.Walk(base, func(pdu gosnmp.SnmpPDU) error {
			labels[indexOf(base, pdu.Name)] = pduString(pdu)
			return nil
		})
	}

	walked := false
	if p.Sensors {
		if ok, err := walkSensors(g, deviceTag, o); ok {
			walked = true
		} else if err != "" {
			lastErr = err
		}
	}
	if p.PoE {
		if ok, err := walkPoE(g, deviceTag, o); ok {
			walked = true
		} else if err != "" {
			lastErr = err
		}
	}
	for _, w := range p.Walk {
		base := normOID(w.OID)
		if err := g.Walk(base, func(pdu gosnmp.SnmpPDU) error {
			v, ok := pduNum(pdu)
			if !ok {
				return nil
			}
			idx := indexOf(base, pdu.Name)
			tags := copyTags(deviceTag)
			tags["index"] = idx
			if name := labels[idx]; name != "" {
				tags["port"] = name
			}
			o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: w.Name, Value: v, Tags: tags})
			return nil
		}); err == nil {
			walked = true
		} else {
			lastErr = "walk " + w.Name + ": " + err.Error()
		}
	}

	if len(o.Metrics) == 0 && len(facts) == 0 && !walked {
		o.Check.Status = "fail"
		if lastErr == "" {
			lastErr = "no snmp data returned"
		}
		o.Check.Error = lastErr
		return
	}
	o.Check.Status = "ok"

	if len(facts) > 0 {
		if payload, err := json.Marshal(facts); err == nil {
			o.InvFacts = append(o.InvFacts, protocol.Fact{Kind: "device", Key: host, Payload: string(payload)})
		}
	}
}

var snmpAuthProtos = map[string]gosnmp.SnmpV3AuthProtocol{
	"MD5": gosnmp.MD5, "SHA": gosnmp.SHA, "SHA224": gosnmp.SHA224,
	"SHA256": gosnmp.SHA256, "SHA384": gosnmp.SHA384, "SHA512": gosnmp.SHA512,
}

var snmpPrivProtos = map[string]gosnmp.SnmpV3PrivProtocol{
	"DES": gosnmp.DES, "AES": gosnmp.AES, "AES192": gosnmp.AES192, "AES256": gosnmp.AES256,
}

func snmpV3(g *gosnmp.GoSNMP, p protocol.Probe, cred secret.Cred) error {
	if cred.User == "" {
		return errors.New("snmpv3: secret with user required")
	}
	usm := &gosnmp.UsmSecurityParameters{UserName: cred.User}
	flags := gosnmp.NoAuthNoPriv
	if p.AuthProto != "" {
		proto, ok := snmpAuthProtos[strings.ToUpper(p.AuthProto)]
		if !ok {
			return errors.New("snmpv3: unknown authProto " + p.AuthProto)
		}
		if cred.Pass == "" {
			return errors.New("snmpv3: auth passphrase missing in secret")
		}
		usm.AuthenticationProtocol = proto
		usm.AuthenticationPassphrase = cred.Pass
		flags = gosnmp.AuthNoPriv
	}
	if p.PrivProto != "" {
		proto, ok := snmpPrivProtos[strings.ToUpper(p.PrivProto)]
		if !ok {
			return errors.New("snmpv3: unknown privProto " + p.PrivProto)
		}
		if cred.Priv == "" {
			return errors.New("snmpv3: privacy passphrase missing in secret (wakora secret set --priv)")
		}
		usm.PrivacyProtocol = proto
		usm.PrivacyPassphrase = cred.Priv
		flags = gosnmp.AuthPriv
	}

	g.Version = gosnmp.Version3
	g.SecurityModel = gosnmp.UserSecurityModel
	g.MsgFlags = flags
	g.SecurityParameters = usm
	g.ContextName = p.Context
	return nil
}

func normOID(oid string) string {
	if strings.HasPrefix(oid, ".") {
		return oid
	}
	return "." + oid
}

func indexOf(base, full string) string {
	base = strings.TrimPrefix(base, ".")
	full = strings.TrimPrefix(full, ".")
	if strings.HasPrefix(full, base+".") {
		return full[len(base)+1:]
	}
	return full
}

func pduNum(pdu gosnmp.SnmpPDU) (float64, bool) {
	switch pdu.Type {
	case gosnmp.OctetString, gosnmp.ObjectIdentifier, gosnmp.IPAddress, gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.Null:
		return 0, false
	default:
		bi := gosnmp.ToBigInt(pdu.Value)
		if bi == nil {
			return 0, false
		}
		f, _ := new(big.Float).SetInt(bi).Float64()
		return f, true
	}
}

func pduString(pdu gosnmp.SnmpPDU) string {
	switch v := pdu.Value.(type) {
	case []byte:
		return string(v)
	case string:
		return v
	default:
		return fmt.Sprintf("%v", v)
	}
}

func copyTags(in map[string]string) map[string]string {
	out := make(map[string]string, len(in)+2)
	for k, v := range in {
		out[k] = v
	}
	return out
}
