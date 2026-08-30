package defs

import "testing"

func TestLogOpenRefusedOnlyMatchesTheLogFailure(t *testing.T) {
	refused := []byte("nginx: [alert] could not open error log file: open() \"/var/log/nginx/error.log\" failed (13: Permission denied)\nnginx: configuration file /etc/nginx/nginx.conf test failed")
	if !logOpenRefused(refused) {
		t.Fatal("the one failure the retry exists for was not recognised")
	}
	if logOpenRefused([]byte("nginx: [emerg] unknown directive \"servr\" in /etc/nginx/sites-enabled/a:3")) {
		t.Fatal("a config syntax error asked for the retry")
	}
	if logOpenRefused([]byte("nginx: invalid option: \"e\"")) {
		t.Fatal("the unsupported-flag answer asked for another retry")
	}
	if logOpenRefused(nil) {
		t.Fatal("empty output asked for a retry")
	}
}
