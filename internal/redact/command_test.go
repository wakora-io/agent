package redact

import (
	"strings"
	"testing"
)

func TestScrubCommandHidesSecretsCronLinesCarry(t *testing.T) {
	cases := map[string]string{
		`curl -fsS https://hc-ping.example.com/5f3c2a9e-1234-4abc-9def-0123456789ab`:               "5f3c2a9e-1234",
		`curl -s "https://app.example.com/?hb=0123456789abcdef0123456789abcdef"`:                   "0123456789abcdef",
		`wget -q -O /dev/null https://hooks.example.com/services/T01/B01/abcdefghij1234567890ABCD`: "abcdefghij1234567890ABCD",
		`curl https://api.example.com/run?job=nightly&region=eu`:                                   "nightly",
		`sshpass -p 'S3cret pass' rsync -a /srv backup@198.51.100.4:/b`:                            "S3cret",
		`sshpass -p hunter2 ssh backup@198.51.100.4`:                                               "hunter2",
		`/opt/backup.sh --key=AbCdEf0123456789AbCdEf0123 --dest s3`:                                "AbCdEf0123456789",
		`/usr/bin/notify AbCdEf0123456789AbCdEf0123+/xyz=`:                                         "AbCdEf0123456789",
	}
	for in, leak := range cases {
		got := ScrubCommand(in)
		if strings.Contains(got, leak) {
			t.Fatalf("secret %q leaked: %q -> %q", leak, in, got)
		}
		if !strings.Contains(got, mask) {
			t.Fatalf("no redaction marker: %q -> %q", in, got)
		}
	}
}

func TestScrubCommandKeepsOrdinaryCronLinesReadable(t *testing.T) {
	for _, in := range []string{
		`cd /var/www/html && php wp-cron.php > /dev/null 2>&1`,
		`/usr/bin/php /var/www/example/artisan schedule:run`,
		`/usr/sbin/logrotate /etc/logrotate.conf`,
		`curl -fsS https://www.example.com/cron/run-nightly-reports`,
		`test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )`,
	} {
		if got := ScrubCommand(in); got != in {
			t.Fatalf("an ordinary cron line was altered: %q -> %q", in, got)
		}
	}
}
