package defs

import "testing"

func TestScanVhostPoolsSiteRootIsTheServerLevelOne(t *testing.T) {
	got := scanVhostPools([]byte(`
server {
	listen 80;
	server_name example.com;
	location /.well-known/acme-challenge/ {
		root /var/www/acme;
	}
	return 301 https://example.com$request_uri;
}
server {
	listen 443 ssl;
	server_name example.com www.example.com;
	root /var/www/example/public;
	location / { root /var/www/other; }
}
server {
	listen 80;
	server_name noroot.example.net;
	location / { proxy_pass http://127.0.0.1:3000; }
}
`))
	if r := got["example.com"].siteRoot; r != "/var/www/example/public" {
		t.Fatalf("example.com site root %q, want the server-level root of the 443 block", r)
	}
	if r := got["www.example.com"].siteRoot; r != "/var/www/example/public" {
		t.Fatalf("www.example.com site root %q", r)
	}
	if r := got["noroot.example.net"].siteRoot; r != "" {
		t.Fatalf("a block without a server-level root read %q", r)
	}
}
