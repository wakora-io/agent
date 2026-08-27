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

func scaleOID(v, scale float64) float64 {
	if scale == 0 {
		return v
	}
	return v * scale
}

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

	preTimeout := 2 * time.Second
	if timeout < preTimeout {
		preTimeout = timeout
	}
	saveTimeout, saveRetries := g.Timeout, g.Retries
	g.Timeout, g.Retries = preTimeout, 0
	_, preErr := g.Get([]string{".1.3.6.1.2.1.1.3.0"})
	g.Timeout, g.Retries = saveTimeout, saveRetries
	if preErr != nil && strings.Contains(strings.ToLower(preErr.Error()), "timeout") {
		o.Check.Status = "fail"
		o.Check.Error = "target did not answer the liveness get - unreachable, powered off or wrong community"
		return
	}

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
				if i >= len(p.DeviceFacts) {
					break
				}
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
				if i >= len(p.Get) {
					break
				}
				if v, ok := pduNum(pdu); ok {
					o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: p.Get[i].Name, Value: scaleOID(v, p.Get[i].Scale), Tags: copyTags(deviceTag)})
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
	if p.Topology {
		if extras, ok, err := walkTopology(g, host, labels, o); ok {
			walked = true
			for k, v := range extras {
				facts[k] = v
			}
		} else if err != "" {
			lastErr = err
		}
	}
	for _, w := range p.Walk {
		base := normOID(w.OID)
		wLabels, tagKey := labels, "port"
		if w.LabelOID != "" {
			wLabels = map[string]string{}
			lb := normOID(w.LabelOID)
			_ = g.Walk(lb, func(pdu gosnmp.SnmpPDU) error {
				wLabels[indexOf(lb, pdu.Name)] = pduString(pdu)
				return nil
			})
			tagKey = "sensor"
			if w.LabelTag != "" {
				tagKey = w.LabelTag
			}
		}
		unitByIdx := map[string]string{}
		if w.UnitOID != "" {
			ub := normOID(w.UnitOID)
			_ = g.Walk(ub, func(pdu gosnmp.SnmpPDU) error {
				unitByIdx[indexOf(ub, pdu.Name)] = pduString(pdu)
				return nil
			})
		}
		if err := g.Walk(base, func(pdu gosnmp.SnmpPDU) error {
			v, ok := pduNum(pdu)
			if !ok {
				return nil
			}
			idx := indexOf(base, pdu.Name)
			tags := copyTags(deviceTag)
			name := wLabels[idx]
			if name != "" && w.LabelOID != "" {
				tags[tagKey] = name
			} else {
				tags["index"] = idx
				if name != "" {
					tags[tagKey] = name
				}
			}
			val := scaleOID(v, w.Scale)
			if u, ok := w.Units[unitByIdx[idx]]; ok {
				tags["unit"] = u.Tag
				val = scaleOID(v, u.Scale)
			}
			o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: w.Name, Value: val, Tags: tags})
			return nil
		}); err == nil {
			walked = true
		} else {
			lastErr = "walk " + w.Name + ": " + err.Error()
		}
	}

	applyLinkState(o, p, host, time.Now())

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
