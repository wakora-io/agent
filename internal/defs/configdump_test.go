package defs

import "testing"

func TestNginxDumpIsUsedEvenWhenNginxComplains(t *testing.T) {
	dump := []byte("# configuration file /etc/nginx/nginx.conf:\nserver {\n\tserver_name site.example;\n}\n")
	if !configDumped("nginx", dump) {
		t.Fatal("a config dump on stdout must be usable no matter what the exit code was")
	}
	if configDumped("nginx", []byte("nginx: [emerg] unknown directive \"srver\" in /etc/nginx/nginx.conf:3\n")) {
		t.Fatal("a broken config produces no dump and must stay a failure")
	}
	if configDumped("nginx", nil) {
		t.Fatal("no output is no dump")
	}
	if configDumped("apache2ctl", []byte("VirtualHost configuration:\n*:443 site.example (/etc/apache2/sites-enabled/a.conf:1)\n")) != true {
		t.Fatal("the apache listing must be usable the same way")
	}
}
