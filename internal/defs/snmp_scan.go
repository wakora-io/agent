package defs

import (
	"encoding/json"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"

	"wakora.io/agent/internal/protocol"
)

const maxScanHosts = 256

func runSNMPScan(o *Outcome, service string, p protocol.Probe, timeout time.Duration, resolve CredResolver) {
	ips, err := expandTargets(p.Targets)
	if err != nil {
		o.Check.Status = "fail"
		o.Check.Error = err.Error()
		return
	}
	o.Check.Target = strings.Join(p.Targets, ",")

	community := "public"
	if p.Secret != "" {
		c, ok := resolve(p.Secret)
		if !ok {
			o.Check.Status = "fail"
			o.Check.Error = "secret " + p.Secret + " not set on host (wakora secret set)"
			return
		}
		if c.Pass != "" {
			community = c.Pass
		}
	}

	perHost := 1500 * time.Millisecond
	if timeout > 0 && timeout < perHost {
		perHost = timeout
	}
	port := uint16(161)
	if p.Port > 0 {
		port = uint16(p.Port)
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	found := 0
	for _, ip := range ips {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			descr, objid, ok := scanOne(ip, port, community, perHost)
			if !ok {
				return
			}
			payload, _ := json.Marshal(map[string]string{"sysDescr": descr, "sysObjectID": objid, "via": service, "port": strconv.Itoa(int(port))})
			mu.Lock()
			found++
			o.InvFacts = append(o.InvFacts, protocol.Fact{Kind: "candidate", Key: ip, Payload: string(payload)})
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	sort.Slice(o.InvFacts, func(i, j int) bool { return o.InvFacts[i].Key < o.InvFacts[j].Key })

	o.Metrics = append(o.Metrics, protocol.MetricPoint{
		Name: "dev.scan.responders", Value: float64(found), Tags: map[string]string{"range": o.Check.Target},
	})
	o.Metrics = append(o.Metrics, protocol.MetricPoint{
		Name: "dev.scan.scanned", Value: float64(len(ips)), Tags: map[string]string{"range": o.Check.Target},
	})
	o.Check.Status = "ok"
}

func scanOne(ip string, port uint16, community string, timeout time.Duration) (descr, objid string, ok bool) {
	g := &gosnmp.GoSNMP{
		Target: ip, Port: port, Version: gosnmp.Version2c, Community: community,
		Timeout: timeout, Retries: 0, MaxOids: 2,
	}
	if err := g.Connect(); err != nil {
		return "", "", false
	}
	defer g.Conn.Close()
	res, err := g.Get([]string{".1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.1.2.0"})
	if err != nil || len(res.Variables) < 2 {
		return "", "", false
	}
	for _, pdu := range res.Variables {
		switch pdu.Type {
		case gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.EndOfMibView, gosnmp.Null:
			return "", "", false
		}
	}
	return pduString(res.Variables[0]), pduString(res.Variables[1]), true
}

func expandTargets(targets []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	add := func(ip string) error {
		if seen[ip] {
			return nil
		}
		seen[ip] = true
		out = append(out, ip)
		if len(out) > maxScanHosts {
			return errScanTooWide
		}
		return nil
	}
	for _, t := range targets {
		t = strings.TrimSpace(t)
		switch {
		case strings.Contains(t, "/"):
			ipnet, err := parseCIDRHosts(t)
			if err != nil {
				return nil, err
			}
			for _, ip := range ipnet {
				if err := add(ip); err != nil {
					return nil, err
				}
			}
		case strings.Contains(t, "-"):
			rng, err := parseDashRange(t)
			if err != nil {
				return nil, err
			}
			for _, ip := range rng {
				if err := add(ip); err != nil {
					return nil, err
				}
			}
		default:
			if net.ParseIP(t) == nil {
				return nil, errScanBadTarget
			}
			if err := add(t); err != nil {
				return nil, err
			}
		}
	}
	if len(out) == 0 {
		return nil, errScanBadTarget
	}
	return out, nil
}

func parseDashRange(t string) ([]string, error) {
	lo, hi, ok := strings.Cut(t, "-")
	if !ok {
		return nil, errScanBadTarget
	}
	loIP := net.ParseIP(strings.TrimSpace(lo)).To4()
	if loIP == nil {
		return nil, errScanBadTarget
	}
	hiStr := strings.TrimSpace(hi)
	var last int
	if strings.Contains(hiStr, ".") {
		hiIP := net.ParseIP(hiStr).To4()
		if hiIP == nil || hiIP[0] != loIP[0] || hiIP[1] != loIP[1] || hiIP[2] != loIP[2] {
			return nil, errScanBadTarget
		}
		last = int(hiIP[3])
	} else {
		n, err := strconv.Atoi(hiStr)
		if err != nil {
			return nil, errScanBadTarget
		}
		last = n
	}
	start := int(loIP[3])
	if last < start || last > 255 {
		return nil, errScanBadTarget
	}
	var out []string
	for i := start; i <= last; i++ {
		out = append(out, net.IPv4(loIP[0], loIP[1], loIP[2], byte(i)).String())
	}
	return out, nil
}

func parseCIDRHosts(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil || ip.To4() == nil {
		return nil, errScanBadTarget
	}
	var out []string
	for cur := ip.Mask(ipnet.Mask); ipnet.Contains(cur); cur = nextIP(cur) {
		out = append(out, cur.String())
		if len(out) > maxScanHosts {
			return nil, errScanTooWide
		}
	}
	return out, nil
}

func nextIP(ip net.IP) net.IP {
	ip = ip.To4()
	out := make(net.IP, 4)
	copy(out, ip)
	for i := 3; i >= 0; i-- {
		out[i]++
		if out[i] != 0 {
			break
		}
	}
	return out
}

type scanErr string

func (e scanErr) Error() string { return string(e) }

const (
	errScanTooWide   scanErr = "scan range too wide (max 256 hosts; operator must narrow the approved range)"
	errScanBadTarget scanErr = "invalid scan target (want ip, a.b.c.d-e, or CIDR)"
)
