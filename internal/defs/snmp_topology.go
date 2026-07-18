package defs

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/gosnmp/gosnmp"

	"wakora.io/agent/internal/protocol"
)

const (
	oidLldpLocChassisSub = ".1.0.8802.1.1.2.1.3.1.0"
	oidLldpLocChassisId  = ".1.0.8802.1.1.2.1.3.2.0"
	oidLldpLocSysName    = ".1.0.8802.1.1.2.1.3.3.0"
	oidLldpRemChassisSub = ".1.0.8802.1.1.2.1.4.1.1.4"
	oidLldpRemChassisId  = ".1.0.8802.1.1.2.1.4.1.1.5"
	oidLldpRemPortSub    = ".1.0.8802.1.1.2.1.4.1.1.6"
	oidLldpRemPortId     = ".1.0.8802.1.1.2.1.4.1.1.7"
	oidLldpRemSysName    = ".1.0.8802.1.1.2.1.4.1.1.9"
	oidIfHighSpeed       = ".1.3.6.1.2.1.31.1.1.1.15"
	oidDot1qTpFdbPort    = ".1.3.6.1.2.1.17.7.1.2.2.1.2"
	oidDot1dTpFdbPort    = ".1.3.6.1.2.1.17.4.3.1.2"
	oidDot1dBaseIfIndex  = ".1.3.6.1.2.1.17.1.4.1.2"
	oidIpNetToMediaPhys  = ".1.3.6.1.2.1.4.22.1.2"
	oidMtxrNbrIP         = ".1.3.6.1.4.1.14988.1.1.11.1.1.2"
	oidMtxrNbrMac        = ".1.3.6.1.4.1.14988.1.1.11.1.1.3"
	oidMtxrNbrIdentity   = ".1.3.6.1.4.1.14988.1.1.11.1.1.6"
	oidMtxrNbrIface      = ".1.3.6.1.4.1.14988.1.1.11.1.1.8"
	oidDot1qVlanName     = ".1.3.6.1.2.1.17.7.1.4.3.1.1"
	oidDot1qPvid         = ".1.3.6.1.2.1.17.7.1.4.5.1.1"

	maxLinkFacts = 64
	maxEdgeMacs  = 32
	maxPortSpeed = 64
	maxFdbTable  = 256
	maxArpTable  = 256
	maxVlans     = 128
)

func macColons(raw []byte) string {
	parts := make([]string, len(raw))
	for i, b := range raw {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, ":")
}

func printableASCII(raw []byte) bool {
	if len(raw) == 0 {
		return false
	}
	for _, b := range raw {
		if b < 0x20 || b > 0x7e {
			return false
		}
	}
	return true
}

func idString(subtype int, raw []byte, macSubtype int) string {
	if subtype == macSubtype && len(raw) == 6 {
		return macColons(raw)
	}
	if printableASCII(raw) {
		return string(raw)
	}
	return macColons(raw)
}

func chassisString(subtype int, raw []byte) string {
	return idString(subtype, raw, 4)
}

func portIdString(subtype int, raw []byte) string {
	return idString(subtype, raw, 3)
}

func lldpRemPort(idx string) string {
	parts := strings.Split(idx, ".")
	if len(parts) == 3 {
		return parts[1]
	}
	return idx
}

func fdbMac(idx string) string {
	parts := strings.Split(idx, ".")
	if len(parts) < 6 {
		return ""
	}
	raw := make([]byte, 6)
	for i, p := range parts[len(parts)-6:] {
		n := 0
		for _, c := range p {
			if c < '0' || c > '9' {
				return ""
			}
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return ""
		}
		raw[i] = byte(n)
	}
	return macColons(raw)
}

func walkBytes(g *gosnmp.GoSNMP, base string) map[string][]byte {
	out := map[string][]byte{}
	_ = g.Walk(base, func(pdu gosnmp.SnmpPDU) error {
		if b, ok := pdu.Value.([]byte); ok {
			out[indexOf(base, pdu.Name)] = b
		} else if s, ok := pdu.Value.(string); ok {
			out[indexOf(base, pdu.Name)] = []byte(s)
		}
		return nil
	})
	return out
}

func getScalar(g *gosnmp.GoSNMP, oid string) (gosnmp.SnmpPDU, bool) {
	res, err := g.Get([]string{oid})
	if err != nil || len(res.Variables) == 0 {
		return gosnmp.SnmpPDU{}, false
	}
	pdu := res.Variables[0]
	if pdu.Type == gosnmp.NoSuchObject || pdu.Type == gosnmp.NoSuchInstance || pdu.Type == gosnmp.Null {
		return gosnmp.SnmpPDU{}, false
	}
	return pdu, true
}

func portName(labels map[string]string, ifIdx string) string {
	if n := labels[ifIdx]; n != "" {
		return n
	}
	return ifIdx
}

func walkTopology(g *gosnmp.GoSNMP, host string, labels map[string]string, o *Outcome) (map[string]string, bool, string) {
	extras := map[string]string{}
	walked := false

	if pdu, ok := getScalar(g, oidLldpLocChassisId); ok {
		sub := 4
		if spdu, ok := getScalar(g, oidLldpLocChassisSub); ok {
			if v, ok := pduNum(spdu); ok {
				sub = int(v)
			}
		}
		if b, ok := pdu.Value.([]byte); ok {
			extras["chassisId"] = chassisString(sub, b)
		} else {
			extras["chassisId"] = pduString(pdu)
		}
		walked = true
	}
	if pdu, ok := getScalar(g, oidLldpLocSysName); ok {
		extras["lldpName"] = pduString(pdu)
	}

	remChassis := walkBytes(g, oidLldpRemChassisId)
	remChassisSub := walkInts(g, oidLldpRemChassisSub)
	remPort := walkBytes(g, oidLldpRemPortId)
	remPortSub := walkInts(g, oidLldpRemPortSub)
	remName := walkBytes(g, oidLldpRemSysName)

	idxs := make([]string, 0, len(remChassis))
	for idx := range remChassis {
		idxs = append(idxs, idx)
	}
	sort.Strings(idxs)
	neighbors := 0
	for _, idx := range idxs {
		if neighbors >= maxLinkFacts {
			break
		}
		chassis := chassisString(remChassisSub[idx], remChassis[idx])
		if chassis == "" {
			continue
		}
		local := lldpRemPort(idx)
		link := map[string]string{
			"localPort": portName(labels, local),
			"chassis":   chassis,
			"src":       "lldp",
		}
		if b, ok := remPort[idx]; ok {
			link["remotePort"] = portIdString(remPortSub[idx], b)
		}
		if b, ok := remName[idx]; ok && printableASCII(b) {
			link["remoteName"] = string(b)
		}
		if payload, err := json.Marshal(link); err == nil {
			o.InvFacts = append(o.InvFacts, protocol.Fact{Kind: "link", Key: host + "|" + portName(labels, local) + "|" + chassis, Payload: string(payload)})
			neighbors++
		}
	}
	nbrIPs := walkStrings(g, oidMtxrNbrIP)
	if len(nbrIPs) > 0 {
		nbrMacs := walkBytes(g, oidMtxrNbrMac)
		nbrNames := walkStrings(g, oidMtxrNbrIdentity)
		nbrIfaces := walkInts(g, oidMtxrNbrIface)
		nidx := make([]string, 0, len(nbrIPs))
		for idx := range nbrIPs {
			nidx = append(nidx, idx)
		}
		sort.Strings(nidx)
		for _, idx := range nidx {
			if neighbors >= maxLinkFacts {
				break
			}
			mac := ""
			if b, ok := nbrMacs[idx]; ok && len(b) == 6 {
				mac = macColons(b)
			}
			end := nbrIPs[idx]
			if end == "" {
				end = mac
			}
			if end == "" {
				continue
			}
			local := portName(labels, fmt.Sprintf("%d", nbrIfaces[idx]))
			link := map[string]string{"localPort": local, "src": "mndp"}
			if mac != "" {
				link["chassis"] = mac
			}
			if nbrIPs[idx] != "" {
				link["toIp"] = nbrIPs[idx]
			}
			if n := nbrNames[idx]; n != "" && printableASCII([]byte(n)) {
				link["remoteName"] = n
			}
			if payload, err := json.Marshal(link); err == nil {
				o.InvFacts = append(o.InvFacts, protocol.Fact{Kind: "link", Key: host + "|" + local + "|" + end, Payload: string(payload)})
				neighbors++
			}
		}
	}
	if neighbors > 0 {
		walked = true
		extras["lldpNeighbors"] = fmt.Sprintf("%d", neighbors)
	}

	speeds := map[string]string{}
	for idx, mbps := range walkInts(g, oidIfHighSpeed) {
		if mbps <= 0 || len(speeds) >= maxPortSpeed {
			continue
		}
		speeds[portName(labels, idx)] = fmt.Sprintf("%d", mbps)
	}
	if len(speeds) > 0 {
		if b, err := json.Marshal(speeds); err == nil {
			extras["portSpeeds"] = string(b)
		}
	}

	bridgeIf := map[string]string{}
	for bp, ifIdx := range walkInts(g, oidDot1dBaseIfIndex) {
		bridgeIf[bp] = fmt.Sprintf("%d", ifIdx)
	}
	fdb := walkInts(g, oidDot1qTpFdbPort)
	if len(fdb) == 0 {
		fdb = walkInts(g, oidDot1dTpFdbPort)
	}
	portMacs := map[string][]string{}
	macPort := map[string]string{}
	for idx, bp := range fdb {
		mac := fdbMac(idx)
		if mac == "" || bp <= 0 {
			continue
		}
		key := fmt.Sprintf("%d", bp)
		portMacs[key] = append(portMacs[key], mac)
		if len(macPort) < maxFdbTable {
			ifIdx := bridgeIf[key]
			if ifIdx == "" {
				ifIdx = key
			}
			macPort[mac] = portName(labels, ifIdx)
		}
	}
	if len(portMacs) > 0 {
		walked = true
		edges := map[string]string{}
		total := 0
		for bp, macs := range portMacs {
			total += len(macs)
			if len(macs) == 1 && len(edges) < maxEdgeMacs {
				ifIdx := bridgeIf[bp]
				if ifIdx == "" {
					ifIdx = bp
				}
				edges[portName(labels, ifIdx)] = macs[0]
			}
		}
		extras["fdbEntries"] = fmt.Sprintf("%d", total)
		if len(edges) > 0 {
			if b, err := json.Marshal(edges); err == nil {
				extras["edgeMacs"] = string(b)
			}
		}
		fp := map[string]any{"macs": macPort}
		if total > len(macPort) {
			fp["truncated"] = 1
		}
		if b, err := json.Marshal(fp); err == nil {
			o.InvFacts = append(o.InvFacts, protocol.Fact{Kind: "fdb", Key: host, Payload: string(b)})
		}
	}

	arpTable := map[string]string{}
	arp := 0
	_ = g.Walk(oidIpNetToMediaPhys, func(pdu gosnmp.SnmpPDU) error {
		arp++
		if len(arpTable) >= maxArpTable {
			return nil
		}
		ip := arpIP(indexOf(oidIpNetToMediaPhys, pdu.Name))
		if ip == "" {
			return nil
		}
		if b, ok := pdu.Value.([]byte); ok && len(b) == 6 {
			arpTable[ip] = macColons(b)
		}
		return nil
	})
	if arp > 0 {
		extras["arpEntries"] = fmt.Sprintf("%d", arp)
	}
	if len(arpTable) > 0 {
		ap := map[string]any{"ips": arpTable}
		if arp > len(arpTable) {
			ap["truncated"] = 1
		}
		if b, err := json.Marshal(ap); err == nil {
			o.InvFacts = append(o.InvFacts, protocol.Fact{Kind: "arp", Key: host, Payload: string(b)})
		}
	}

	vlanNames := walkStrings(g, oidDot1qVlanName)
	pvids := walkInts(g, oidDot1qPvid)
	if len(vlanNames) > 0 || len(pvids) > 0 {
		walked = true
		vp := map[string]any{}
		if len(vlanNames) > 0 {
			names := map[string]string{}
			for id, n := range vlanNames {
				if len(names) >= maxVlans {
					break
				}
				names[id] = n
			}
			vp["vlans"] = names
		}
		if len(pvids) > 0 {
			m := map[string]string{}
			for bp, vid := range pvids {
				if len(m) >= maxPortSpeed {
					break
				}
				ifIdx := bridgeIf[bp]
				if ifIdx == "" {
					ifIdx = bp
				}
				m[portName(labels, ifIdx)] = fmt.Sprintf("%d", vid)
			}
			vp["pvid"] = m
		}
		if b, err := json.Marshal(vp); err == nil {
			o.InvFacts = append(o.InvFacts, protocol.Fact{Kind: "vlan", Key: host, Payload: string(b)})
		}
	}

	if !walked && len(extras) == 0 {
		return extras, false, "no lldp/fdb tables"
	}
	return extras, true, ""
}

func arpIP(idx string) string {
	parts := strings.Split(idx, ".")
	if len(parts) < 4 {
		return ""
	}
	return strings.Join(parts[len(parts)-4:], ".")
}
