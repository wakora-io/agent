package defs

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"wakora.io/agent/internal/atomicfile"
	"wakora.io/agent/internal/discovery"
	"wakora.io/agent/internal/protocol"
)

func Verify(set protocol.DefinitionSet, publisherKey string, tenantKey ed25519.PublicKey) []protocol.Definition {
	pub, err := base64.StdEncoding.DecodeString(publisherKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		log.Print("defs: no valid publisher key built in, rejecting all definitions")
		return nil
	}
	var out []protocol.Definition
	for _, sd := range set.Definitions {
		sig, err := base64.StdEncoding.DecodeString(sd.Sig)
		if err != nil {
			log.Print("defs: signature invalid, definition rejected")
			continue
		}
		if sd.Tier == "tenant" {
			if len(tenantKey) != ed25519.PublicKeySize || !ed25519.Verify(tenantKey, sd.Def, sig) {
				log.Print("defs: tenant signature invalid, community definition rejected")
				continue
			}
		} else if !ed25519.Verify(ed25519.PublicKey(pub), sd.Def, sig) {
			log.Print("defs: signature invalid, definition rejected")
			continue
		}
		var d protocol.Definition
		if err := json.Unmarshal(sd.Def, &d); err != nil || d.Service == "" {
			log.Print("defs: malformed definition rejected")
			continue
		}
		if sd.Tier == "tenant" && !strings.HasPrefix(d.Service, "community_") {
			log.Printf("defs: community definition %q outside the community_ namespace, rejected", d.Service)
			continue
		}
		out = append(out, d)
	}
	return out
}

func TenantDefsKey(stateDir string, set protocol.DefinitionSet) ed25519.PublicKey {
	hasTenant := false
	for _, sd := range set.Definitions {
		if sd.Tier == "tenant" {
			hasTenant = true
			break
		}
	}
	if !hasTenant || set.TenantKey == "" {
		return nil
	}
	cand, err := base64.StdEncoding.DecodeString(set.TenantKey)
	if err != nil || len(cand) != ed25519.PublicKeySize {
		return nil
	}
	pinPath := filepath.Join(stateDir, "tenant-defs.pub")
	if raw, err := os.ReadFile(pinPath); err == nil && len(raw) > 0 {
		pinned, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if err == nil && len(pinned) == ed25519.PublicKeySize {
			if !bytes.Equal(pinned, cand) {
				log.Printf("defs: community key mismatch - tenant-tier definitions rejected (reset: remove %s)", pinPath)
				return nil
			}
			return ed25519.PublicKey(pinned)
		}
	}
	if err := atomicfile.Write(pinPath, []byte(set.TenantKey+"\n"), 0o600); err != nil {
		log.Printf("defs: community key pin failed: %v", err)
		return nil
	}
	log.Print("defs: community definitions key pinned on first use")
	return ed25519.PublicKey(cand)
}

func VerifyUninstallOrder(envelope, publisherKey, wantUUID string) bool {
	pub, err := base64.StdEncoding.DecodeString(publisherKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	dot := strings.LastIndexByte(envelope, '.')
	if dot <= 0 {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(envelope[:dot])
	if err != nil {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(envelope[dot+1:])
	if err != nil || !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		return false
	}
	var o struct {
		UUID     string `json:"uuid"`
		IssuedAt int64  `json:"issuedAt"`
	}
	if json.Unmarshal(payload, &o) != nil {
		return false
	}
	return o.UUID != "" && o.UUID == wantUUID
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
	hasProcess := func(want string) bool {
		for _, f := range facts {
			if f.Kind != "process" {
				continue
			}
			if f.Key == want {
				return true
			}
			var info struct {
				Exe string `json:"exe"`
			}
			if json.Unmarshal([]byte(f.Payload), &info) == nil && info.Exe != "" && path.Base(info.Exe) == want {
				return true
			}
		}
		return false
	}
	m := d.Match
	if m.Process == "" && m.ProcessPrefix == "" && m.Port == "" && m.Package == "" && m.Unit == "" && m.Init == "" && m.Capability == "" {
		return false
	}
	if m.Capability != "" && !HasCapability(facts, m.Capability) {
		return false
	}
	if m.Process != "" && !hasProcess(m.Process) {
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

func HasCapability(facts []discovery.Fact, key string) bool {
	for _, f := range facts {
		if f.Kind != "capability" || f.Key != key {
			continue
		}
		var info struct {
			Available string `json:"available"`
		}
		if json.Unmarshal([]byte(f.Payload), &info) == nil && info.Available == "1" {
			return true
		}
	}
	return false
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
