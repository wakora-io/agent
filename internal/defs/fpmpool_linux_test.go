//go:build linux

package defs

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestParseFpmPoolConf(t *testing.T) {
	out := map[string]fpmPoolLimit{}
	parseFpmPoolConf(`
[global]
pid = /run/php-fpm.pid

[www]
listen = /run/php/php8.3-fpm.sock
pm = static
pm.max_children = 12 ; tuneda
; listen = /ignored/comment.sock

[shop.example.com]
listen = /run/php/$pool.sock
pm = ondemand
pm.max_children = 40
`, out)
	if len(out) != 2 {
		t.Fatalf("pools: %v", out)
	}
	if out["www"].listen != "/run/php/php8.3-fpm.sock" || out["www"].maxChildren != 12 || out["www"].mode != "static" {
		t.Fatalf("www: %+v", out["www"])
	}
	if out["shop.example.com"].mode != "ondemand" {
		t.Fatalf("mode: %+v", out["shop.example.com"])
	}
	if out["shop.example.com"].listen != "/run/php/shop.example.com.sock" || out["shop.example.com"].maxChildren != 40 {
		t.Fatalf("pool var: %+v", out["shop.example.com"])
	}
	parseFpmPoolConf("[www]\nlisten = 127.0.0.1:9000\npm.max_children = 8\n", out)
	if out["www"].maxChildren != 20 {
		t.Fatalf("same-name pools must sum max_children, got %d", out["www"].maxChildren)
	}
	if out["www"].listen != "/run/php/php8.3-fpm.sock" {
		t.Fatalf("first listen wins on collision, got %q", out["www"].listen)
	}
}

func TestFpmWorkerCensus(t *testing.T) {
	root := t.TempDir()
	mk := func(pid, cmdline, stat string) {
		dir := filepath.Join(root, pid)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(cmdline), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("101", "php-fpm: pool www\x00\x00", "101 (php-fpm8.2) S 1 101 101 0 -1 4194624 1 0 0 0 1 1 0 0 20 0 1 0 1 1 1 1")
	mk("102", "php-fpm: pool www\x00", "102 (php-fpm8.2) D 1 102 102 0 -1 4194624 1 0 0 0 1 1 0 0 20 0 1 0 1 1 1 1")
	mk("103", "php-fpm: pool shop.example.com\x00", "103 (php-fpm8.2) R 1 103 103 0 -1 4194624 1 0 0 0 1 1 0 0 20 0 1 0 1 1 1 1")
	mk("104", "php-fpm: master process (/etc/php/8.3/fpm/php-fpm.conf)\x00", "104 (php-fpm8.2) S 1 104 104 0 -1 4194624 1 0 0 0 1 1 0 0 20 0 1 0 1 1 1 1")
	mk("105", "nginx: worker process\x00", "105 (nginx) S 1 105 105 0 -1 4194624 1 0 0 0 1 1 0 0 20 0 1 0 1 1 1 1")
	mk("notpid", "garbage", "garbage")

	got := fpmWorkerCensus(root)
	if len(got) != 2 {
		t.Fatalf("pools: %+v", got)
	}
	if got["www"].workers != 2 || got["www"].blocked != 1 {
		t.Fatalf("www: %+v", got["www"])
	}
	if got["shop.example.com"].workers != 1 || got["shop.example.com"].blocked != 0 {
		t.Fatalf("shop: %+v", got)
	}
}

func TestParseUnixDiagDump(t *testing.T) {
	ne := binary.NativeEndian
	path := "/run/php/www.sock\x00"
	nameLen := 4 + len(path)
	rqLen := 4 + 8
	payloadLen := 16 + nlaAlign(nameLen) + rqLen
	msgLen := 16 + payloadLen

	buf := make([]byte, nlaAlign(msgLen)+16)
	ne.PutUint32(buf[0:4], uint32(msgLen))
	ne.PutUint16(buf[4:6], 20)
	p := buf[16:]
	p[0] = 1
	p[2] = 10
	a := p[16:]
	ne.PutUint16(a[0:2], uint16(nameLen))
	ne.PutUint16(a[2:4], 0)
	copy(a[4:], path)
	a = a[nlaAlign(nameLen):]
	ne.PutUint16(a[0:2], uint16(rqLen))
	ne.PutUint16(a[2:4], 4)
	ne.PutUint32(a[4:8], 7)
	ne.PutUint32(a[8:12], 128)

	done := buf[nlaAlign(msgLen):]
	ne.PutUint32(done[0:4], 16)
	ne.PutUint16(done[4:6], 3)

	out := map[string]uint32{}
	finished, err := parseUnixDiagDump(buf, out)
	if err != nil || !finished {
		t.Fatalf("finished=%v err=%v", finished, err)
	}
	if out["/run/php/www.sock"] != 7 {
		t.Fatalf("backlog: %v", out)
	}
}

func TestParseTCPListenBacklogs(t *testing.T) {
	raw := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:2328 00000000:0000 0A 00000000:00000005 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 100 0 0 10 0
   2: 0100007F:0BB8 0200007F:1F90 01 00000000:00000009 00:00000000 00000000     0        0 12347 1 0000000000000000 100 0 0 10 0
`
	out := map[int]uint32{}
	parseTCPListenBacklogs(raw, out)
	if out[9000] != 5 {
		t.Fatalf("port 9000 backlog: %v", out)
	}
	if out[80] != 0 {
		t.Fatalf("port 80 backlog: %v", out)
	}
	if _, ok := out[3000]; ok {
		t.Fatal("established rows must not count")
	}
}

func TestListenBacklogRouting(t *testing.T) {
	unixQ := map[string]uint32{"/run/php/www.sock": 3}
	tcpQ := map[int]uint32{9000: 4}
	if q, ok := listenBacklog("/run/php/www.sock", unixQ, tcpQ); !ok || q != 3 {
		t.Fatalf("unix: %v %v", q, ok)
	}
	if q, ok := listenBacklog("127.0.0.1:9000", unixQ, tcpQ); !ok || q != 4 {
		t.Fatalf("tcp: %v %v", q, ok)
	}
	if q, ok := listenBacklog("9000", unixQ, tcpQ); !ok || q != 4 {
		t.Fatalf("bare port: %v %v", q, ok)
	}
	if _, ok := listenBacklog("/run/php/other.sock", unixQ, tcpQ); ok {
		t.Fatal("unknown listener must not emit")
	}
	if _, ok := listenBacklog("", unixQ, tcpQ); ok {
		t.Fatal("empty listen must not emit")
	}
}
