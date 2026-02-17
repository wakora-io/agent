package defs

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"log"
	"strings"

	"wakora.io/agent/internal/discovery"
	"wakora.io/agent/internal/protocol"
)

func Verify(set protocol.DefinitionSet, publisherKey string) []protocol.Definition {
	pub, err := base64.StdEncoding.DecodeString(publisherKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		log.Print("defs: no valid publisher key built in, rejecting all definitions")
		return nil
	}
	var out []protocol.Definition
	for _, sd := range set.Definitions {
		sig, err := base64.StdEncoding.DecodeString(sd.Sig)
		if err != nil || !ed25519.Verify(ed25519.PublicKey(pub), sd.Def, sig) {
			log.Print("defs: signature invalid, definition rejected")
			continue
		}
		var d protocol.Definition
		if err := json.Unmarshal(sd.Def, &d); err != nil || d.Service == "" {
			log.Print("defs: malformed definition rejected")
			continue
		}
		out = append(out, d)
	}
	return out
}

func Matches(d protocol.Definition, facts []discovery.Fact) bool {
	has := func(kind, key string) bool {
		for _, f := range facts {
			if f.Kind == kind && f.Key == key {
				return true
			}
		}
		return false
	}
	hasPrefix := func(kind, prefix string) bool {
		for _, f := range facts {
			if f.Kind == kind && strings.HasPrefix(f.Key, prefix) {
				return true
			}
		}
		return false
	}
	m := d.Match
	if m.Process == "" && m.ProcessPrefix == "" && m.Port == "" && m.Package == "" && m.Unit == "" && m.Init == "" {
		return false
	}
	if m.Process != "" && !has("process", m.Process) {
		return false
	}
	if m.ProcessPrefix != "" && !hasPrefix("process", m.ProcessPrefix) {
		return false
	}
	if m.Port != "" && !has("port", m.Port) {
		return false
	}
	if m.Package != "" && !has("package", m.Package) {
		return false
	}
	if m.Unit != "" && !has("unit", m.Unit) {
		return false
	}
	if m.Init != "" {
		if m.Init == "*" {
			ok := false
			for _, f := range facts {
				if f.Kind == "init" {
					ok = true
					break
				}
			}
			if !ok {
				return false
			}
		} else if !has("init", m.Init) {
			return false
		}
	}
	return true
}

func ProcFacts(facts []discovery.Fact, p protocol.Probe) map[string]string {
	prefix := p.Process
	if prefix == "" {
		return nil
	}
	for _, f := range facts {
		if f.Kind != "process" || !strings.HasPrefix(f.Key, prefix) {
			continue
		}
		var info struct {
			Cmdline string `json:"cmdline"`
			Exe     string `json:"exe"`
		}
		if json.Unmarshal([]byte(f.Payload), &info) != nil {
			continue
		}
		body := []byte(f.Key + "\x00" + info.Cmdline + "\x00" + info.Exe)
		out := map[string]string{}
		for _, r := range p.Facts {
			if v, ok := extract(body, r.Regex); ok {
				out[r.Name] = v
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return nil
}
