//go:build linux

package defs

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"wakora.io/agent/internal/protocol"
	"wakora.io/agent/internal/secret"
)

func linstorTestServer(t *testing.T, wantToken string) *httptest.Server {
	t.Helper()
	oldMs := (time.Now().Unix() - 172800) * 1000
	freshMs := (time.Now().Unix() - 600) * 1000
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if wantToken != "" && r.Header.Get("Authorization") != "Bearer "+wantToken {
			w.WriteHeader(401)
			return
		}
		switch {
		case r.URL.Path == "/v1/nodes":
			w.Write([]byte(`[
				{"name":"node-a","type":"Combined","connection_status":"ONLINE","net_interfaces":[{"name":"default","address":"192.0.2.1","is_active":true}]},
				{"name":"node-b","type":"Satellite","connection_status":"ONLINE","net_interfaces":[{"name":"failsafe","address":"198.51.100.2","is_active":true},{"name":"default","address":"192.0.2.2","is_active":false}]},
				{"name":"node-c","type":"Satellite","connection_status":"OFFLINE","net_interfaces":[{"name":"default","address":"192.0.2.3","is_active":true}]}
			]`))
		case r.URL.Path == "/v1/view/storage-pools":
			w.Write([]byte(`[
				{"storage_pool_name":"linstor","node_name":"node-a","provider_kind":"LVM_THIN","free_capacity":100,"total_capacity":1000},
				{"storage_pool_name":"linstor","node_name":"node-b","provider_kind":"LVM_THIN","free_capacity":900,"total_capacity":1000},
				{"storage_pool_name":"DfltDisklessStorPool","node_name":"node-a","provider_kind":"DISKLESS","free_capacity":0,"total_capacity":0}
			]`))
		case r.URL.Path == "/v1/error-reports":
			w.Write([]byte(`[{"node_name":"node-a","error_time":` + strconv.FormatInt(freshMs, 10) + `}]`))
		case r.URL.Path == "/v1/controller/version":
			w.Write([]byte(`{"version":"1.34.0","rest_api_version":"1.28.0"}`))
		case r.URL.Path == "/v1/view/snapshots":
			w.Write([]byte(`[
				{"name":"snap_pm-aaa_vzdump","resource_name":"pm-aaa","snapshots":[{"node_name":"node-a","create_timestamp":` + strconv.FormatInt(oldMs, 10) + `}]},
				{"name":"snap_pm-bbb_vzdump","resource_name":"pm-bbb","snapshots":[{"node_name":"node-a","create_timestamp":` + strconv.FormatInt(freshMs, 10) + `}]},
				{"name":"manual-keep","resource_name":"pm-ccc","snapshots":[{"node_name":"node-a","create_timestamp":` + strconv.FormatInt(oldMs, 10) + `}]}
			]`))
		default:
			w.WriteHeader(404)
		}
	}))
}

func linstorVal(o *Outcome, name, tagKey, tagVal string) (float64, bool) {
	for _, m := range o.Metrics {
		if m.Name != name {
			continue
		}
		if tagKey == "" || m.Tags[tagKey] == tagVal {
			return m.Value, true
		}
	}
	return 0, false
}

func TestLinstorReadsTheControllerView(t *testing.T) {
	srv := linstorTestServer(t, "tok123")
	defer srv.Close()
	o := &Outcome{}
	p := protocol.Probe{URLs: []string{srv.URL}, Secret: "linstor-controller"}
	runLinstor(o, "linstor", p, func(string) (secret.Cred, bool) { return secret.Cred{Pass: "tok123"}, true })

	if o.Check.Status != "ok" {
		t.Fatalf("check must be ok, got %s %s", o.Check.Status, o.Check.Error)
	}
	if v, _ := linstorVal(o, "svc.linstor.node.online", "node", "node-c"); v != 0 {
		t.Fatalf("offline node must read 0, got %v", v)
	}
	if v, _ := linstorVal(o, "svc.linstor.nodes_online", "", ""); v != 2 {
		t.Fatalf("two online expected, got %v", v)
	}
	if v, ok := linstorVal(o, "svc.linstor.netif.on_default", "node", "node-b"); !ok || v != 0 {
		t.Fatalf("node-b rides the failsafe netif, got %v %v", v, ok)
	}
	if v, ok := linstorVal(o, "svc.linstor.netif.on_default", "node", "node-c"); !ok || v != 1 {
		t.Fatalf("node-c rides default, got %v %v", v, ok)
	}
	if v, ok := linstorVal(o, "svc.linstor.netif.on_default", "node", "node-a"); !ok || v != 1 {
		t.Fatalf("a combined node carries a satellite netif verdict too, got %v %v", v, ok)
	}
	if v, _ := linstorVal(o, "svc.linstor.pool.free_pct", "pool", "linstor@node-a"); v != 10 {
		t.Fatalf("node-a pool free pct, got %v", v)
	}
	if _, ok := linstorVal(o, "svc.linstor.pool.free_pct", "pool", "DfltDisklessStorPool@node-a"); ok {
		t.Fatal("diskless pools carry no capacity")
	}
	if v, _ := linstorVal(o, "svc.linstor.error_reports_hour", "", ""); v != 1 {
		t.Fatalf("one report in the hour, got %v", v)
	}
	if v, _ := linstorVal(o, "svc.linstor.stale_snapshots", "", ""); v != 1 {
		t.Fatalf("one stale vzdump snapshot (fresh one and manual-keep excluded), got %v", v)
	}
	if !strings.Contains(o.Facts["staleSnaps"], "pm-aaa") {
		t.Fatalf("stale sample must name pm-aaa, got %q", o.Facts["staleSnaps"])
	}
	if !strings.Contains(o.Facts["failover"], "node-b via failsafe") {
		t.Fatalf("failover fact, got %q", o.Facts["failover"])
	}
	if o.Facts["version"] != "1.34.0" {
		t.Fatalf("controller version fact, got %q", o.Facts["version"])
	}
	if o.Check.Target != srv.URL {
		t.Fatalf("check target must name the answering base, got %q", o.Check.Target)
	}
}

func TestDrbdVersionParsesProcHeader(t *testing.T) {
	raw := "version: 9.2.9 (api:2/proto:86-122)\nGIT-hash: 12345 build by @node-a, 2026-01-01\n"
	if m := drbdVerRe.FindStringSubmatch(raw); m == nil || m[1] != "9.2.9" {
		t.Fatalf("kernel version must parse, got %v", m)
	}
}

func TestLinstorAuthFailureCarriesTheHint(t *testing.T) {
	srv := linstorTestServer(t, "tok123")
	defer srv.Close()
	o := &Outcome{}
	p := protocol.Probe{URLs: []string{srv.URL}}
	runLinstor(o, "linstor", p, func(string) (secret.Cred, bool) { return secret.Cred{}, false })
	if o.Check.Status != "fail" || !strings.Contains(o.Check.Error, "wakora secret set linstor-controller") {
		t.Fatalf("auth fail must hint the secret command, got %s %s", o.Check.Status, o.Check.Error)
	}
}
