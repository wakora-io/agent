//go:build linux

package discovery

import (
	"strings"
	"testing"
)

func TestCronCommandIsScrubbedBeforeItLeavesTheHost(t *testing.T) {
	agg := map[string]*cronInfo{}
	line := `/usr/bin/mysqldump -u root -pSuperSecret123 db | gzip > /backup/db.gz`
	addCronEntry(agg, "root", line, "0 3 * * *", "/etc/crontab")

	if len(agg) != 1 {
		t.Fatalf("entry not recorded: %+v", agg)
	}
	for key := range agg {
		if strings.Contains(key, "SuperSecret123") {
			t.Fatalf("the password rode into the fact key: %s", key)
		}
		if !strings.Contains(key, "mysqldump") {
			t.Fatalf("the job is no longer recognisable: %s", key)
		}
	}
}

func TestAnOrdinaryCronJobIsLeftAlone(t *testing.T) {
	agg := map[string]*cronInfo{}
	line := "/usr/bin/certbot renew --quiet --post-hook 'systemctl reload nginx'"
	addCronEntry(agg, "root", line, "17 4 * * *", "/etc/crontab")

	for key := range agg {
		if key != "root:"+line {
			t.Fatalf("a job with nothing to hide was rewritten: %s", key)
		}
	}
}
