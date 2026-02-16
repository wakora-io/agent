package discovery

import (
	"encoding/json"
	"net"
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
	ip := primaryIP()
	if ip == "" {
		return nil
	}
	payload, err := json.Marshal(map[string]string{"ip": ip})
	if err != nil {
		return nil
	}
	return []Fact{{Kind: "net", Key: "primary_ip", Payload: string(payload)}}
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
