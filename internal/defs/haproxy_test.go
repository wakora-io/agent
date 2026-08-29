package defs

import "testing"

func TestHAProxyStatMetrics(t *testing.T) {
	csv := `# pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,dreq,dresp,ereq,econ,eresp,wretr,wredis,status,weight,act,bck,chkfail,chkdown,lastchg,downtime,qlimit,pid,iid,sid,throttle,lbtot,tracked,type,rate,rate_lim,rate_max,check_status,check_code,check_duration,hrsp_1xx,hrsp_2xx,hrsp_3xx,hrsp_4xx,hrsp_5xx,hrsp_other,hanafail
web,FRONTEND,,,3,5,2000,120,10000,50000,0,0,2,,,,,OPEN,,,,,,,,,1,2,0,,,,0,4,0,9,,,,0,100,5,10,7,0,
web,srv-good,0,0,2,3,,80,5000,25000,,0,,0,0,0,0,UP,1,1,0,0,0,3600,0,,1,2,1,,60,,2,3,,,L4OK,,1,0,70,3,5,2,0,
web,srv-dead,0,0,0,0,,0,0,0,,0,,5,0,0,0,DOWN,1,0,0,3,1,120,120,,1,2,2,,0,,2,0,,,L4TOUT,,1001,0,0,0,0,0,0,
web,BACKEND,0,0,2,3,200,80,5000,25000,0,0,,5,1,0,0,UP,1,1,0,,1,120,120,,1,2,0,,60,,1,3,,,,,,0,70,3,5,9,0,
broken,BACKEND,0,0,0,0,200,4,100,200,0,0,,4,0,0,0,DOWN,0,0,0,,1,60,60,,1,3,0,,4,,1,0,,,,,,0,0,0,0,4,0,`

	pts := haproxyStatMetrics("svc.haproxy.", csv)
	get := func(name, tagK, tagV string) (float64, bool) {
		for _, p := range pts {
			if p.Name != name {
				continue
			}
			if tagK == "" || p.Tags[tagK] == tagV {
				return p.Value, true
			}
		}
		return 0, false
	}

	if v, ok := get("svc.haproxy.backends_up", "", ""); !ok || v != 1 {
		t.Fatalf("backends_up = %v, want 1 (web UP, broken DOWN)", v)
	}
	if v, _ := get("svc.haproxy.backends_total", "", ""); v != 2 {
		t.Fatalf("backends_total = %v, want 2", v)
	}
	if v, _ := get("svc.haproxy.servers_up", "", ""); v != 1 {
		t.Fatalf("servers_up = %v, want 1", v)
	}
	if v, _ := get("svc.haproxy.servers_total", "", ""); v != 2 {
		t.Fatalf("servers_total = %v, want 2", v)
	}

	if v, ok := get("svc.haproxy.server.up", "server", "srv-dead"); !ok || v != 0 {
		t.Fatalf("srv-dead up = %v, want 0", v)
	}
	if v, ok := get("svc.haproxy.server.up", "server", "srv-good"); !ok || v != 1 {
		t.Fatalf("srv-good up = %v, want 1", v)
	}
	if v, ok := get("svc.haproxy.proxy.hrsp_5xx_total", "kind", "backend"); !ok || v != 9 {
		t.Fatalf("web backend 5xx = %v, want 9", v)
	}
	if v, ok := get("svc.haproxy.proxy.sessions", "kind", "frontend"); !ok || v != 3 {
		t.Fatalf("frontend scur = %v, want 3", v)
	}
	if v, ok := get("svc.haproxy.proxy.conn_errors_total", "kind", "backend"); !ok || v != 5 {
		t.Fatalf("backend econ = %v, want 5", v)
	}
}

func TestParseHAProxyInfo(t *testing.T) {
	raw := "Name: HAProxy\nVersion: 2.8.10\nUptime_sec: 4242\nCurrConns: 7\nConnRate: 3\n"
	kv := parseHAProxyInfo(raw)
	if kv["Version"] != "2.8.10" || kv["CurrConns"] != "7" {
		t.Fatalf("info parse wrong: %v", kv)
	}
}
