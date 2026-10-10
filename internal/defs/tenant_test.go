package defs

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"wakora.io/agent/internal/protocol"
)

func tenantSigned(t *testing.T, priv ed25519.PrivateKey, def string) protocol.SignedDefinition {
	t.Helper()
	sd := signDef(t, priv, def)
	sd.Tier = "tenant"
	return sd
}

func TestVerifyTenantTier(t *testing.T) {
	pubPub, pubPriv, _ := ed25519.GenerateKey(rand.Reader)
	pubB64 := base64.StdEncoding.EncodeToString(pubPub)
	tenPub, tenPriv, _ := ed25519.GenerateKey(rand.Reader)

	official := signDef(t, pubPriv, `{"service":"nginx","match":{"process":"nginx"},"probes":[]}`)
	community := tenantSigned(t, tenPriv, `{"service":"community_myapp","match":{"process":"myapp"},"probes":[]}`)

	set := protocol.DefinitionSet{Definitions: []protocol.SignedDefinition{official, community}}
	got := Verify(set, pubB64, tenPub)
	if len(got) != 2 {
		t.Fatalf("official + community must both verify, got %d", len(got))
	}

	if got := Verify(set, pubB64, nil); len(got) != 1 || got[0].Service != "nginx" {
		t.Fatalf("without a tenant key only the official definition may pass, got %d", len(got))
	}

	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if got := Verify(set, pubB64, otherPub); len(got) != 1 {
		t.Fatalf("a community definition signed by a DIFFERENT tenant key must be rejected, got %d", len(got))
	}

	device := tenantSigned(t, tenPriv, `{"service":"device_192_0_2_10","match":{"process":"x"},"probes":[]}`)
	set = protocol.DefinitionSet{Definitions: []protocol.SignedDefinition{device}}
	if got := Verify(set, pubB64, tenPub); len(got) != 1 || got[0].Service != "device_192_0_2_10" {
		t.Fatalf("a tenant-signed device_ definition must verify, got %d", len(got))
	}

	shadow := tenantSigned(t, tenPriv, `{"service":"nginx","match":{"process":"nginx"},"probes":[]}`)
	set = protocol.DefinitionSet{Definitions: []protocol.SignedDefinition{shadow}}
	if got := Verify(set, pubB64, tenPub); len(got) != 0 {
		t.Fatal("a tenant-signed definition must not claim a name outside community_/device_ (official shadowing)")
	}

	forged := signDef(t, tenPriv, `{"service":"nginx","match":{"process":"nginx"},"probes":[]}`)
	set = protocol.DefinitionSet{Definitions: []protocol.SignedDefinition{forged}}
	if got := Verify(set, pubB64, tenPub); len(got) != 0 {
		t.Fatal("an official-tier definition signed by the tenant key must be rejected")
	}
}

func TestTenantDefsKeyPinsOnFirstUse(t *testing.T) {
	dir := t.TempDir()
	tenPub, tenPriv, _ := ed25519.GenerateKey(rand.Reader)
	keyB64 := base64.StdEncoding.EncodeToString(tenPub)
	community := tenantSigned(t, tenPriv, `{"service":"community_x","match":{"process":"x"},"probes":[]}`)

	noTenant := protocol.DefinitionSet{TenantKey: keyB64}
	if k := TenantDefsKey(dir, noTenant); k != nil {
		t.Fatal("a set without community definitions must not resolve (or pin) a key")
	}
	if _, err := os.Stat(filepath.Join(dir, "tenant-defs.pub")); err == nil {
		t.Fatal("no pin file may appear before the first community definition")
	}

	withTenant := protocol.DefinitionSet{TenantKey: keyB64, Definitions: []protocol.SignedDefinition{community}}
	if k := TenantDefsKey(dir, withTenant); k == nil {
		t.Fatal("first use must pin and return the offered key")
	}
	if k := TenantDefsKey(dir, withTenant); k == nil {
		t.Fatal("the same key must keep verifying on later pushes")
	}

	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	swapped := protocol.DefinitionSet{TenantKey: base64.StdEncoding.EncodeToString(otherPub), Definitions: []protocol.SignedDefinition{community}}
	if k := TenantDefsKey(dir, swapped); k != nil {
		t.Fatal("a DIFFERENT key after the pin must be rejected - that is the whole TOFU point")
	}
}

func TestPinnedKeyMismatchReportsInsteadOfSilence(t *testing.T) {
	dir := t.TempDir()
	pinPub, pinPriv, _ := ed25519.GenerateKey(rand.Reader)
	first := protocol.DefinitionSet{TenantKey: base64.StdEncoding.EncodeToString(pinPub), Definitions: []protocol.SignedDefinition{tenantSigned(t, pinPriv, `{"service":"community_x","match":{"process":"x"},"probes":[]}`)}}
	if TenantDefsKey(dir, first) == nil {
		t.Fatal("first use must pin")
	}
	if why := TenantPinRefusal(dir, first); why != "" {
		t.Fatalf("the pinned key itself is no refusal, got %q", why)
	}

	newPub, newPriv, _ := ed25519.GenerateKey(rand.Reader)
	device := tenantSigned(t, newPriv, `{"service":"device_192_0_2_10","hosts":["collector-a"],"intervalSec":60,"probes":[{"name":"snmp","type":"snmp","target":"192.0.2.10","secret":"snmp-device"}]}`)
	shadow := tenantSigned(t, newPriv, `{"service":"nginx","probes":[{"name":"x","type":"exec","command":"systemctl"}]}`)
	moved := protocol.DefinitionSet{TenantKey: base64.StdEncoding.EncodeToString(newPub), Definitions: []protocol.SignedDefinition{device, shadow}}
	if TenantDefsKey(dir, moved) != nil {
		t.Fatal("a different key must stay refused")
	}
	why := TenantPinRefusal(dir, moved)
	if why == "" {
		t.Fatal("a refused key must come with a reason")
	}
	got := RefusedTenant(moved, why)
	if len(got) != 1 || got[0].Service != "device_192_0_2_10" {
		t.Fatalf("only names inside the tenant namespaces may be reported, got %+v", got)
	}
	if len(got[0].Hosts) != 1 || got[0].Hosts[0] != "collector-a" || got[0].IntervalSec != 60 {
		t.Fatalf("the collector role and cadence must survive, got %+v", got[0])
	}
	p := got[0].Probes[0]
	if p.Denied != why || p.Secret != "" || p.Target != "" {
		t.Fatalf("a refused probe must carry the reason and nothing it could act on, got %+v", p)
	}
	o := DeniedOutcome(got[0].Service, p)
	if o.Check.Status != "fail" || o.Check.CheckID != "device_192_0_2_10/snmp" || o.Check.Target != "" {
		t.Fatalf("the refusal must reach the platform as a failing check without a target, got %+v", o.Check)
	}
}
