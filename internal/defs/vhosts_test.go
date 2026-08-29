package defs

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestResolveApachePath(t *testing.T) {
	cases := []struct{ raw, logDir, want string }{
		{"${APACHE_LOG_DIR}/access.log", "/var/log/apache2", "/var/log/apache2/access.log"},
		{"$APACHE_LOG_DIR/other.log", "/logs", "/logs/other.log"},
		{"/absolute/custom.log", "/var/log/apache2", "/absolute/custom.log"},
		{"relative.log", "/var/log/apache2", "/var/log/apache2/relative.log"},
		{"${UNRESOLVED}/x.log", "/var/log/apache2", ""},
	}
	for _, c := range cases {
		if got := resolveApachePath(c.raw, c.logDir); got != c.want {
			t.Errorf("resolveApachePath(%q,%q)=%q want %q", c.raw, c.logDir, got, c.want)
		}
	}
}

const nginxDump = `
# configuration file /etc/nginx/nginx.conf:
user www-data;
http {
	# server_names_hash_bucket_size 64;
	server {
		listen 80 default_server;
		listen [::]:80 default_server;
		server_name _;
		location / {
			try_files $uri $uri/ =404;
		}
	}
	server {
		listen 443 ssl;
		listen 8443;
		server_name example.com www.example.com;
		location / { proxy_pass http://127.0.0.1:3000; }
	}
}
`

func TestParseNginxVhosts(t *testing.T) {
	hosts := parseNginxVhosts([]byte(nginxDump))
	want := map[string]bool{
		"_:80":                false,
		"example.com:443":     true,
		"example.com:8443":    false,
		"www.example.com:443": true, "www.example.com:8443": false,
	}
	if len(hosts) != len(want) {
		t.Fatalf("got %d vhosts: %+v", len(hosts), hosts)
	}
	for _, h := range hosts {
		key := fmt.Sprintf("%s:%d", h.Name, h.Port)
		ssl, ok := want[key]
		if !ok {
			t.Fatalf("unexpected vhost %s", key)
		}
		if h.SSL != ssl {
			t.Fatalf("%s ssl=%v want %v", key, h.SSL, ssl)
		}
	}
}

const nginxPanelDump = "# configuration file /etc/nginx/nginx.conf:\n" +
	"http {\n" +
	"\tserver_names_hash_bucket_size 128;\n" +
	"\tserver_tokens off;\n" +
	"\tupstream backend {\n" +
	"\t\tserver 10.0.0.1:8080;\n" +
	"\t}\n" +
	"# configuration file /etc/nginx/sites-enabled/a.example.lv.conf:\n" +
	"server {\n" +
	"\tlisten\t80;\n" +
	"\tserver_name\ta.example.lv www.a.example.lv;\n" +
	"\taccess_log /www/a.example.lv/log/access.log;\n" +
	"}\n" +
	"# configuration file /etc/nginx/sites-enabled/b.conf:\n" +
	"server {\n" +
	"    listen 443 ssl; server_name b.example.lv;\n" +
	"}\n" +
	"# configuration file /etc/nginx/sites-enabled/c.conf:\n" +
	"server\n" +
	"{\n" +
	"    listen 8080;\n" +
	"    server_name c.example.lv\n" +
	"                www.c.example.lv;\n" +
	"}\n" +
	"}\n"

func TestParseNginxVhostsPanelLayouts(t *testing.T) {
	hosts := parseNginxVhosts([]byte(nginxPanelDump))
	want := map[string]bool{
		"a.example.lv:80":       false,
		"www.a.example.lv:80":   false,
		"b.example.lv:443":      true,
		"c.example.lv:8080":     false,
		"www.c.example.lv:8080": false,
	}
	if len(hosts) != len(want) {
		t.Fatalf("got %d vhosts: %+v", len(hosts), hosts)
	}
	for _, h := range hosts {
		key := fmt.Sprintf("%s:%d", h.Name, h.Port)
		ssl, ok := want[key]
		if !ok {
			t.Fatalf("unexpected vhost %s", key)
		}
		if h.SSL != ssl {
			t.Fatalf("%s ssl=%v want %v", key, h.SSL, ssl)
		}
	}
}

func TestParseNginxVhostsPrimaryPerBlock(t *testing.T) {
	hosts := parseNginxVhosts([]byte(nginxPanelDump))
	primary := map[string]bool{}
	for _, h := range hosts {
		primary[fmt.Sprintf("%s:%d", h.Name, h.Port)] = h.Primary
	}
	for key, want := range map[string]bool{
		"a.example.lv:80":       true,
		"www.a.example.lv:80":   false,
		"b.example.lv:443":      true,
		"c.example.lv:8080":     true,
		"www.c.example.lv:8080": false,
	} {
		if primary[key] != want {
			t.Errorf("%s primary=%v want %v", key, primary[key], want)
		}
	}
}

const nginxRedirectDump = `
http {
	server {
		listen 80;
		server_name shop.example.com www.shop.example.com;
		return 301 https://shop.example.com$request_uri;
	}
	server {
		listen 443 ssl;
		server_name shop.example.com www.shop.example.com;
		location / { fastcgi_pass unix:/run/php/fpm.sock; }
	}
	server {
		if ($host = www.example.org) {
			return 301 https://$host$request_uri;
		} # managed by Certbot
		if ($host = example.org) {
			return 301 https://$host$request_uri;
		} # managed by Certbot
		listen 80;
		server_name example.org www.example.org;
		return 404; # managed by Certbot
	}
	server {
		listen 80;
		server_name app.example.net;
		location /go { return 301 https://elsewhere.example.com/; }
		location / { fastcgi_pass unix:/run/php/app.sock; }
	}
	server {
		listen 80;
		listen 443 ssl;
		server_name old.example.com;
		rewrite ^(.*)$ https://new.example.com$1 permanent;
	}
	server {
		listen 80;
		server_name rel.example.com;
		return 301 /maintenance.html;
	}
	server {
		listen 80;
		server_name canon.example.com www.canon.example.com;
		return 301 https://www.$host$request_uri;
	}
}
`

func TestParseNginxRedirectBlocks(t *testing.T) {
	hosts := parseNginxVhosts([]byte(nginxRedirectDump))
	got := map[string]string{}
	for _, h := range hosts {
		got[fmt.Sprintf("%s:%d", h.Name, h.Port)] = h.Redirect
	}
	for key, want := range map[string]string{
		"shop.example.com:80":      "shop.example.com",
		"www.shop.example.com:80":  "shop.example.com",
		"shop.example.com:443":     "",
		"www.shop.example.com:443": "",
		"example.org:80":           "example.org",
		"www.example.org:80":       "www.example.org",
		"app.example.net:80":       "",
		"old.example.com:80":       "new.example.com",
		"old.example.com:443":      "new.example.com",
		"rel.example.com:80":       "",
		"canon.example.com:80":     "www.canon.example.com",
		"www.canon.example.com:80": "www.www.canon.example.com",
	} {
		if _, ok := got[key]; !ok {
			t.Fatalf("vhost %s missing: %+v", key, got)
		}
		if got[key] != want {
			t.Errorf("%s redirect=%q want %q", key, got[key], want)
		}
	}
}

func TestRedirectTargetHost(t *testing.T) {
	cases := []struct {
		target string
		want   string
		ok     bool
	}{
		{"https://$host$request_uri", nginxRedirSelf, true},
		{"$scheme://$host$request_uri", nginxRedirSelf, true},
		{"https://$server_name$request_uri", nginxRedirSelf, true},
		{"https://shop.example.com$request_uri", "shop.example.com", true},
		{"https://Example.COM/path?a=1", "example.com", true},
		{"http://a.example.com:8080/x", "a.example.com", true},
		{"https://www.$host$request_uri", "www." + nginxRedirSelf, true},
		{"https://www.$host:8443$request_uri", "www." + nginxRedirSelf, true},
		{"https://$host.example.com/", "", false},
		{"https://other.example.com/x?from=$host", "other.example.com", true},
		{"/maintenance.html", "", false},
		{"https://", "", false},
		{"ftp://example.com", "", false},
	}
	for _, c := range cases {
		got, ok := redirectTargetHost(c.target)
		if got != c.want || ok != c.ok {
			t.Errorf("redirectTargetHost(%q) = %q,%v want %q,%v", c.target, got, ok, c.want, c.ok)
		}
	}
}

const apacheTurnkeyDump = `
VirtualHost configuration:
*:12322                localhost (/etc/apache2/sites-enabled/adminer.conf:3)
*:80                   localhost (/etc/apache2/sites-enabled/wordpress.conf:3)
*:443                  localhost (/etc/apache2/sites-enabled/wordpress.conf:9)
ServerRoot: "/etc/apache2"
Main DocumentRoot: "/var/www/html"
`

const apacheNamevhostDump = `
VirtualHost configuration:
*:80                   is a NameVirtualHost
         default server web1.example.com (/etc/apache2/sites-enabled/000-web1.conf:1)
         port 80 namevhost web1.example.com (/etc/apache2/sites-enabled/000-web1.conf:1)
         port 80 namevhost web2.example.com (/etc/apache2/sites-enabled/010-web2.conf:1)
`

func TestParseApacheVhostsSingle(t *testing.T) {
	hosts := parseApacheVhosts([]byte(apacheTurnkeyDump))
	if len(hosts) != 3 {
		t.Fatalf("got %d vhosts: %+v", len(hosts), hosts)
	}
	ports := map[int]bool{}
	for _, h := range hosts {
		if h.Name != "localhost" {
			t.Fatalf("unexpected name %q", h.Name)
		}
		ports[h.Port] = h.SSL
	}
	if !ports[443] || ports[80] || ports[12322] {
		t.Fatalf("ssl flags wrong: %v", ports)
	}
}

func TestParseApacheVhostsNamed(t *testing.T) {
	hosts := parseApacheVhosts([]byte(apacheNamevhostDump))
	names := map[string]bool{}
	for _, h := range hosts {
		if h.Port != 80 {
			t.Fatalf("unexpected port %d", h.Port)
		}
		names[h.Name] = true
	}
	if !names["web1.example.com"] || !names["web2.example.com"] {
		t.Fatalf("names missing: %v", names)
	}
}

func TestVhostWindowSmallPortfolioProbesAll(t *testing.T) {
	s := &vhostCursorSet{cursors: map[string]int{}}
	got := s.window("nginx", 40, 100)
	if len(got) != 40 {
		t.Fatalf("want all 40, got %d", len(got))
	}
	for i, v := range got {
		if v != i {
			t.Fatalf("want identity order, got %v", got)
		}
	}
}

func TestVhostWindowRotationCoversEverything(t *testing.T) {
	s := &vhostCursorSet{cursors: map[string]int{}}
	n, budget := 269, 100
	seen := map[int]int{}
	for cycle := 0; cycle < 3; cycle++ {
		w := s.window("nginx", n, budget)
		if len(w) != budget {
			t.Fatalf("cycle %d: want %d, got %d", cycle, budget, len(w))
		}
		for _, v := range w {
			seen[v]++
		}
	}
	if len(seen) != n {
		t.Fatalf("3 cycles x 100 over 269 must cover all sites, covered %d", len(seen))
	}
	for v, c := range seen {
		if c > 2 {
			t.Fatalf("site %d probed %d times in 3 cycles", v, c)
		}
	}
}

func TestVhostWindowPerServiceCursor(t *testing.T) {
	s := &vhostCursorSet{cursors: map[string]int{}}
	a1 := s.window("nginx", 200, 100)
	b1 := s.window("apache", 200, 100)
	if a1[0] != 0 || b1[0] != 0 {
		t.Fatalf("independent cursors expected, got nginx=%d apache=%d", a1[0], b1[0])
	}
	a2 := s.window("nginx", 200, 100)
	if a2[0] != 100 {
		t.Fatalf("nginx cursor must advance to 100, got %d", a2[0])
	}
}

func TestDNSProbeName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"shop.example.lv", "shop.example.lv"},
		{"WWW.Example.COM", "www.example.com"},
		{".example.com", "example.com"},
		{"xn--e1afmkfd.org", "xn--e1afmkfd.org"},
		{"_", ""},
		{"localhost", ""},
		{"intranet", ""},
		{"192.168.0.10", ""},
		{"*.example.com", ""},
		{"~^www\\d+\\.example\\.com$", ""},
		{"printer.local", ""},
		{"router.home", ""},
		{"db.internal", ""},
		{"wp.test", ""},
	}
	for _, c := range cases {
		if got := dnsProbeName(c.in); got != c.want {
			t.Errorf("dnsProbeName(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestVhostDNSSweepClassifies(t *testing.T) {
	orig := vhostLookupHost
	defer func() { vhostLookupHost = orig }()
	vhostLookupHost = func(ctx context.Context, name string) ([]string, error) {
		switch name {
		case "alive.example.com":
			return []string{"203.0.113.10"}, nil
		case "dead.example.com":
			return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
		default:
			return nil, &net.DNSError{Err: "i/o timeout", Name: name, IsTimeout: true}
		}
	}
	got := vhostDNSSweep([]string{"alive.example.com", "dead.example.com", "flaky.example.com"}, time.Second)
	if v, ok := got["alive.example.com"]; !ok || !v.alive || len(v.ips) != 1 {
		t.Fatalf("alive misclassified: %v", got)
	}
	if v, ok := got["dead.example.com"]; !ok || v.alive {
		t.Fatalf("NXDOMAIN misclassified: %v", got)
	}
	if _, ok := got["flaky.example.com"]; ok {
		t.Fatalf("transient failure must stay unknown: %v", got)
	}
}

func TestVhostDNSSweepBailsOnDeadResolver(t *testing.T) {
	orig := vhostLookupHost
	defer func() { vhostLookupHost = orig }()
	calls := 0
	vhostLookupHost = func(ctx context.Context, name string) ([]string, error) {
		calls++
		return nil, &net.DNSError{Err: "connection refused", Name: name}
	}
	names := make([]string, 40)
	for i := range names {
		names[i] = fmt.Sprintf("site%d.example.com", i)
	}
	got := vhostDNSSweep(names, time.Second)
	if len(got) != 0 {
		t.Fatalf("dead resolver must report nothing, got %v", got)
	}
	if calls >= 40 {
		t.Fatalf("sweep must abandon a dead resolver early, made %d lookups", calls)
	}
}

func TestScanStickyPools(t *testing.T) {
	conf := []byte(`
server {
	server_name a.example.com;
	location ~ \.php$ {
		fastcgi_pass unix:/run/php/php8.1-fpm.sock;
		fastcgi_param PHP_ADMIN_VALUE "open_basedir=/www/a:/tmp/";
	}
}
server {
	server_name b.example.com;
	location ~ \.php$ {
		fastcgi_pass unix:/run/php/php8.1-fpm.sock;
	}
}
server {
	server_name c.example.com;
	location ~ \.php$ {
		fastcgi_pass unix:/run/php/site-c.sock;
		fastcgi_param PHP_ADMIN_VALUE "open_basedir=/www/c:/tmp/";
	}
}
server {
	server_name d.example.com;
	# fastcgi_param PHP_ADMIN_VALUE "open_basedir=/commented/";
	location ~ \.php$ {
		fastcgi_pass unix:/run/php/php8.2-fpm.sock;
	}
}
server {
	server_name e.example.com;
	location ~ \.php$ {
		fastcgi_pass unix:/run/php/php8.2-fpm.sock;
	}
}
`)
	got := scanStickyPools(conf)
	if !strings.Contains(got, "php8.1-fpm.sock shared by 2 vhosts, 1 set PHP_ADMIN_VALUE") {
		t.Fatalf("shared pool with an admin value must be flagged, got %q", got)
	}
	if strings.Contains(got, "site-c.sock") {
		t.Fatalf("a dedicated pool is fine no matter its admin values, got %q", got)
	}
	if strings.Contains(got, "php8.2-fpm.sock") {
		t.Fatalf("a shared pool WITHOUT admin values is fine, got %q", got)
	}
	if clean := scanStickyPools([]byte("server {\n\tserver_name x;\n\tfastcgi_pass unix:/a.sock;\n}\n")); clean != "" {
		t.Fatalf("clean config must yield an empty fact, got %q", clean)
	}
}

func TestVhostUnixBackend(t *testing.T) {
	for _, c := range []struct {
		pass string
		want string
	}{
		{"unix:/run/php/a.sock;", "/run/php/a.sock"},
		{"/run/php/b.sock", "/run/php/b.sock"},
		{"127.0.0.1:9000", ""},
		{"php_upstream", ""},
		{"unix:/run/php/$ver.sock", ""},
		{"", ""},
	} {
		got, ok := vhostUnixBackend(c.pass)
		if (c.want == "") == ok || got != c.want {
			t.Fatalf("pass %q: got %q ok=%v, want %q", c.pass, got, ok, c.want)
		}
	}
}

func TestScanVhostPools(t *testing.T) {
	conf := []byte(`
server {
	server_name example.com www.example.com;
	root /var/www/example;
	location ~ \.php$ {
		fastcgi_pass unix:/run/php/php7.4-fpm.sock;
	}
}
server {
	server_name a.example.lv;
	location ~ \.php$ {
		fastcgi_pass unix:/run/php/a.sock;
	}
}
server {
	server_name static.example.com;
}
server {
	server_name rootonly.example.com;
	root /var/www/rootonly;
}
`)
	got := scanVhostPools(conf)
	if got["example.com"].pass != "unix:/run/php/php7.4-fpm.sock" || got["www.example.com"].pass != "unix:/run/php/php7.4-fpm.sock" {
		t.Fatalf("every server_name alias must map to the block pool, got %v", got)
	}
	if got["example.com"].root != "/var/www/example" {
		t.Fatalf("block root lost: %v", got["example.com"])
	}
	if got["a.example.lv"].pass != "unix:/run/php/a.sock" {
		t.Fatalf("dedicated pool lost: %v", got)
	}
	if _, ok := got["static.example.com"]; ok {
		t.Fatalf("a vhost with neither pool nor root must not map: %v", got)
	}
	if got["rootonly.example.com"].root != "/var/www/rootonly" {
		t.Fatalf("a php-less vhost with a root must still map for wp detection: %v", got)
	}
}

func TestVhostOffloaded(t *testing.T) {
	publicIP.Store("")
	local := map[string]bool{"10.0.0.5": true}

	if _, known := vhostOffloaded(dnsSweepResult{alive: true, ips: []string{"203.0.113.4"}}, local, nil); known {
		t.Fatal("without the gateway-told public ip the verdict must stay unknown")
	}

	SetPublicIP("203.0.113.50")
	if off, known := vhostOffloaded(dnsSweepResult{alive: true, ips: []string{"198.51.100.54"}}, hostAddrSet(), nil); !known || !off {
		t.Fatal("cdn ip must be offloaded")
	}
	if off, known := vhostOffloaded(dnsSweepResult{alive: true, ips: []string{"203.0.113.50"}}, hostAddrSet(), nil); !known || off {
		t.Fatal("own public ip must not be offloaded")
	}
	if off, known := vhostOffloaded(dnsSweepResult{alive: true, ips: []string{"198.51.100.54", "203.0.113.50"}}, hostAddrSet(), nil); !known || off {
		t.Fatal("any own ip in the answer keeps the vhost local")
	}
	if _, known := vhostOffloaded(dnsSweepResult{alive: false}, hostAddrSet(), nil); known {
		t.Fatal("nxdomain must not vote on offloading")
	}
}

func TestVhostOffloadedCDNRanges(t *testing.T) {
	defer publicIP.Store("")
	publicIP.Store("")
	cdn := cdnNets("172.64.0.0/13 104.16.0.0/13 2606:4700::/32 not-a-cidr")
	if len(cdn) != 3 {
		t.Fatalf("cdn parse: want 3 nets, got %d", len(cdn))
	}

	local := map[string]bool{"192.168.0.7": true}
	if off, known := vhostOffloaded(dnsSweepResult{alive: true, ips: []string{"172.67.133.140"}}, local, cdn); !known || !off {
		t.Fatal("a cdn range hit must give the offloaded verdict without any public ip knowledge")
	}
	if off, known := vhostOffloaded(dnsSweepResult{alive: true, ips: []string{"2606:4700::1"}}, local, cdn); !known || !off {
		t.Fatal("ipv6 cdn ranges must match too")
	}
	if off, known := vhostOffloaded(dnsSweepResult{alive: true, ips: []string{"192.168.0.7"}}, local, cdn); !known || off {
		t.Fatal("a name resolving to an own interface is local even without the public ip")
	}
	if off, known := vhostOffloaded(dnsSweepResult{alive: true, ips: []string{"192.168.0.7", "172.67.133.140"}}, local, cdn); !known || off {
		t.Fatal("an own address in the answer outranks a cdn hit")
	}
	if _, known := vhostOffloaded(dnsSweepResult{alive: true, ips: []string{"203.0.113.4"}}, local, cdn); known {
		t.Fatal("a plain public ip without cdn hit and without own public ip stays withheld")
	}
}

func TestVhostCNAMESweep(t *testing.T) {
	orig := vhostLookupCNAME
	defer func() { vhostLookupCNAME = orig }()
	vhostLookupCNAME = func(_ context.Context, name string) (string, error) {
		switch name {
		case "shop.example.com":
			return "e1234.a.AkamaiEdge.net.", nil
		case "blog.example.com":
			return "blog.example.com.", nil
		case "dead.example.com":
			return "", fmt.Errorf("lookup timeout")
		}
		return "other.example.net.", nil
	}
	suffixes := cdnNameSuffixes(".akamaiedge.net .edgekey.net garbage .x")
	if len(suffixes) != 2 {
		t.Fatalf("suffix parse: want 2, got %v", suffixes)
	}
	got := vhostCNAMESweep([]string{"shop.example.com", "blog.example.com", "dead.example.com", "plain.example.com"}, suffixes, time.Second)
	if !got["shop.example.com"] {
		t.Fatal("an akamai cname must classify as cdn")
	}
	if got["blog.example.com"] || got["dead.example.com"] || got["plain.example.com"] {
		t.Fatalf("only the cname hit classifies: %v", got)
	}
}

func TestPublicIPRejectsUnroutable(t *testing.T) {
	defer publicIP.Store("")
	for _, ip := range []string{"192.168.0.5", "10.0.0.7", "172.16.4.9", "127.0.0.1", "169.254.10.1", "100.64.3.7", "fd00::1", "::1", "not-an-ip"} {
		publicIP.Store("")
		SetPublicIP(ip)
		if got, _ := publicIP.Load().(string); got != "" {
			t.Fatalf("%s is not routable on the public internet, it must not be stored, got %q", ip, got)
		}
		if _, known := vhostOffloaded(dnsSweepResult{alive: true, ips: []string{"203.0.113.4"}}, hostAddrSet(), nil); known {
			t.Fatalf("%s must leave the offloaded verdict withheld", ip)
		}
	}
	for _, ip := range []string{"203.0.113.50", "198.51.100.8", "2001:db8::1"} {
		publicIP.Store("")
		SetPublicIP(ip)
		if got, _ := publicIP.Load().(string); got != ip {
			t.Fatalf("%s is a real public address and must be kept, got %q", ip, got)
		}
	}
}
