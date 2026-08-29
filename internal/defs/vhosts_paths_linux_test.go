//go:build linux

package defs

import (
	"os"
	"testing"
)

func TestVhostBackendGone(t *testing.T) {
	dir := t.TempDir()
	live := dir + "/live.sock"
	if err := os.WriteFile(live, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	svc := "vhostbackendtest"
	vhostPoolsCache.Store(svc, map[string]vhostScanInfo{
		"alive.example.com":  {pass: "unix:" + live},
		"broken.example.com": {pass: "unix:" + dir + "/gone.sock"},
		"remote.example.com": {pass: "127.0.0.1:9000"},
		"static.example.com": {root: dir},
	})
	got := vhostBackendGone(svc)
	if v, ok := got["broken.example.com"]; !ok || !v {
		t.Fatalf("a vhost pointing at a socket that does not exist must read missing, got %v", got)
	}
	if v, ok := got["alive.example.com"]; !ok || v {
		t.Fatalf("a vhost whose socket exists must read present, got %v", got)
	}
	for _, name := range []string{"remote.example.com", "static.example.com"} {
		if _, ok := got[name]; ok {
			t.Fatalf("%s carries no unix backend, so it gets no verdict, got %v", name, got)
		}
	}
}

func TestApacheVhostRoots(t *testing.T) {
	dir := t.TempDir()
	conf := dir + "/wp01.conf"
	if err := os.WriteFile(conf, []byte("<VirtualHost *:80>\n\tServerName wp01.test\n\tDocumentRoot /var/www/wp01\n</VirtualHost>\n"), 0644); err != nil {
		t.Fatal(err)
	}
	out := []byte("VirtualHost configuration:\n*:80  is a NameVirtualHost\n\t default server wp01.test (" + conf + ":1)\n\t port 80 namevhost wp01.test (" + conf + ":1)\n\t port 80 namevhost blog.test (/nonexistent/blog.conf:1)\n")
	got := apacheVhostRoots(out)
	if got["wp01.test"] != "/var/www/wp01" {
		t.Fatalf("documentroot lost: %v", got)
	}
	if _, ok := got["blog.test"]; ok {
		t.Fatalf("unreadable config must not map: %v", got)
	}
}

func TestFpmListenMinors(t *testing.T) {
	dir := t.TempDir()
	deb := dir + "/php/7.4/fpm/pool.d"
	if err := os.MkdirAll(deb, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(deb+"/example.conf", []byte("[example]\nlisten = /run/php/php7.4-fpm.sock\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	remi := dir + "/remi/php83/php-fpm.d"
	if err := os.MkdirAll(remi, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(remi+"/www.conf", []byte("[www]\nlisten = 127.0.0.1:9000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := fpmListenPools(dir+"/php/*/fpm/pool.d/*.conf", dir+"/remi/php*/php-fpm.d/*.conf")
	if got["/run/php/php7.4-fpm.sock"].Minor != "7.4" {
		t.Fatalf("deb socket minor: %v", got)
	}
	if got["127.0.0.1:9000"].Minor != "8.3" {
		t.Fatalf("remi tcp minor: %v", got)
	}
	if got["/run/php/php7.4-fpm.sock"].Prepend != "" {
		t.Fatalf("no prepend directive must read empty, got %q", got["/run/php/php7.4-fpm.sock"].Prepend)
	}
}

func TestFpmListenPoolsPrependOverride(t *testing.T) {
	dir := t.TempDir()
	deb := dir + "/php/8.2/fpm/pool.d"
	if err := os.MkdirAll(deb, 0o755); err != nil {
		t.Fatal(err)
	}
	conf := "[example]\nlisten = /run/php/example.sock\nphp_admin_value[auto_prepend_file] = /www/panel/init.php\n"
	if err := os.WriteFile(deb+"/example.conf", []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	empty := "[bare]\nlisten = /run/php/bare.sock\nphp_admin_value[auto_prepend_file] =\n"
	if err := os.WriteFile(deb+"/bare.conf", []byte(empty), 0o644); err != nil {
		t.Fatal(err)
	}
	got := fpmListenPools(dir + "/php/*/fpm/pool.d/*.conf")
	if got["/run/php/example.sock"].Prepend != "/www/panel/init.php" {
		t.Fatalf("prepend override lost: %v", got)
	}
	if got["/run/php/bare.sock"].Prepend != "none" {
		t.Fatalf("an EMPTY admin prepend blocks ours too and must read none, got %q", got["/run/php/bare.sock"].Prepend)
	}
}
