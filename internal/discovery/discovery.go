package discovery

import (
	"encoding/json"
	"net"
	"runtime"
	"sort"
	"strings"
)

type Fact struct {
	Kind    string
	Key     string
	Payload string
}

type procInfo struct {
	Count   int    `json:"count"`
	Pid     int    `json:"pid"`
	Cmdline string `json:"cmdline,omitempty"`
	Exe     string `json:"exe,omitempty"`
}

type packageInfo struct {
	Version string `json:"version,omitempty"`
}

func netFacts() []Fact {
	var facts []Fact
	if ip := primaryIP(); ip != "" {
		if payload, err := json.Marshal(map[string]string{"ip": ip}); err == nil {
			facts = append(facts, Fact{Kind: "net", Key: "primary_ip", Payload: string(payload)})
		}
	}
	for _, a := range allIPs() {
		payload, err := json.Marshal(map[string]string{"ip": a.ip, "scope": a.scope})
		if err != nil {
			continue
		}
		facts = append(facts, Fact{Kind: "net", Key: "ip:" + a.ip, Payload: string(payload)})
	}
	return facts
}

type ipInfo struct {
	ip    string
	scope string
}

// allIPs lists every address on up interfaces except loopback and link-local;
// private/ULA/CGN ranges are internal, the rest of global unicast is external
func allIPs() []ipInfo {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	cgn := net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}
	seen := map[string]bool{}
	var out []ipInfo
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP == nil {
				continue
			}
			ip := ipn.IP
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
				continue
			}
			key := ip.String()
			if seen[key] {
				continue
			}
			seen[key] = true
			scope := "external"
			if ip.IsPrivate() || cgn.Contains(ip) {
				scope = "internal"
			}
			out = append(out, ipInfo{ip: key, scope: scope})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ip < out[j].ip })
	return out
}

func primaryIP() string {
	if conn, err := net.Dial("udp", "8.8.8.8:53"); err == nil {
		la, ok := conn.LocalAddr().(*net.UDPAddr)
		conn.Close()
		if ok && la.IP != nil {
			return la.IP.String()
		}
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.IsGlobalUnicast() {
				return ipn.IP.String()
			}
		}
	}
	return ""
}

func hostFact() Fact {
	kv := map[string]string{"os": runtime.GOOS, "arch": runtime.GOARCH}
	for k, v := range osDetails() {
		if v != "" {
			kv[k] = v
		}
	}
	payload, _ := json.Marshal(kv)
	return Fact{Kind: "host", Key: "os", Payload: string(payload)}
}

func CountByKind(facts []Fact) map[string]int {
	out := map[string]int{}
	for _, f := range facts {
		out[f.Kind]++
	}
	return out
}

func containerCgroup(s string) bool {
	for _, marker := range []string{"docker-", "/docker/", "libpod-", "kubepods", "cri-containerd", "/lxc/", "lxc.payload"} {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}

func sortedFacts[T any](kind string, agg map[string]*T) []Fact {
	keys := make([]string, 0, len(agg))
	for k := range agg {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	facts := make([]Fact, 0, len(keys))
	for _, k := range keys {
		payload, err := json.Marshal(agg[k])
		if err != nil {
			continue
		}
		facts = append(facts, Fact{Kind: kind, Key: k, Payload: string(payload)})
	}
	return facts
}
