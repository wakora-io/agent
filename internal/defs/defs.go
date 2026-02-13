package defs

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"log"

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
	m := d.Match
	if m.Process == "" && m.Port == "" && m.Package == "" && m.Unit == "" {
		return false
	}
	if m.Process != "" && !has("process", m.Process) {
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
	return true
}
