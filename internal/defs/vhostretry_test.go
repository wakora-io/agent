package defs

import "testing"

func TestLogOpenRefusedOnlyMatchesTheLogFailure(t *testing.T) {
	refused := []byte("nginx: [alert] could not open error log file: open() \"/var/log/nginx/error.log\" failed (13: Permission denied)\nnginx: configuration file /etc/nginx/nginx.conf test failed")
	if !logOpenRefused(refused) {
		t.Fatal("the one failure the retry exists for was not recognised")
	}
	// a real config error must NOT trigger a retry: the second attempt would
	// fail the same way and only cost another dump of a large config tree
	if logOpenRefused([]byte("nginx: [emerg] unknown directive \"servr\" in /etc/nginx/sites-enabled/a:3")) {
		t.Fatal("a config syntax error asked for the retry")
	}
	// an nginx older than 1.19.5 has no -e at all, which is exactly why the
	// retry is second and never first
	if logOpenRefused([]byte("nginx: invalid option: \"e\"")) {
		t.Fatal("the unsupported-flag answer asked for another retry")
	}
	if logOpenRefused(nil) {
		t.Fatal("empty output asked for a retry")
	}
}
