package defs

import "wakora.io/agent/internal/protocol"

var knownProbeTypes = map[string]bool{
	"http": true, "tcp": true, "exec": true, "vhosts": true, "sql": true,
	"redis": true, "snmp": true, "snmpscan": true, "docker": true, "file": true,
	"pve": true, "haproxy": true, "domain": true, "ext": true, "wineventlog": true,
	"logtail": true, "journal": true, "procfact": true, "traps": true, "syslog": true,
	"keepalived": true, "virsh": true, "iis": true, "hyperv": true, "ebpfhttp": true, "apmphp": true, "apmprofile": true, "apmdotnet": true,
	"apmdotnetprofile": true, "k8s": true,
}

func UnsupportedProbes(d protocol.Definition) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range d.Probes {
		if !knownProbeTypes[p.Type] && !seen[p.Type] {
			seen[p.Type] = true
			out = append(out, p.Type)
		}
	}
	return out
}
