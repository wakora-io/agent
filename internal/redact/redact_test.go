package redact

import "strings"

import "testing"

func TestScrubKeepsTheKeyAndDropsTheValue(t *testing.T) {
	got := Scrub(`password=hunter2`)
	if got != "password=***" {
		t.Fatalf("got %q", got)
	}
}

func TestScrubCoversQuotedValuesWithSpaces(t *testing.T) {
	cases := []string{
		`password="my secret pass"`,
		`token: 'a b c'`,
		`--password "two words"`,
	}
	for _, in := range cases {
		got := Scrub(in)
		if strings.Contains(got, "secret pass") || strings.Contains(got, "a b c") || strings.Contains(got, "two words") {
			t.Fatalf("value leaked past the redaction: %q -> %q", in, got)
		}
		if !strings.Contains(got, "***") {
			t.Fatalf("no redaction marker: %q -> %q", in, got)
		}
	}
}

func TestScrubCoversMysqlStyleFlags(t *testing.T) {
	got := Scrub(`/usr/bin/mysqldump -u root -pS3cr3t wordpress`)
	if strings.Contains(got, "S3cr3t") {
		t.Fatalf("attached -p value leaked: %q", got)
	}
	if !strings.Contains(got, "-u root") {
		t.Fatalf("the rest of the command line was swallowed: %q", got)
	}
	got = Scrub(`curl -u user:S3cr3t https://example.com/x`)
	if strings.Contains(got, "S3cr3t") {
		t.Fatalf("curl user:pass value leaked: %q", got)
	}
}

func TestScrubLeavesForeignFlagsAlone(t *testing.T) {
	for _, in := range []string{
		`/usr/sbin/ntpd -p /var/run/ntpd.pid -g -u 109:115`,
		`/usr/sbin/xinetd -pidfile /run/xinetd.pid -stayalive`,
		`/usr/bin/docker-proxy -proto tcp -host-port 3001`,
		`/usr/sbin/varnishd -T localhost:6082 -S /etc/varnish/secret -p feature=+http2`,
		`psql -p 5432 -h db`,
		`sshd -p 2222`,
	} {
		if got := Scrub(in); got != in {
			t.Fatalf("a foreign flag was mangled: %q -> %q", in, got)
		}
	}
}

func TestScrubKeepsUrlsReadableWhileDroppingTheCredential(t *testing.T) {
	got := Scrub(`a-service --database http://dbuser:s3cr3tvalue@198.51.100.10:8123`)
	if strings.Contains(got, "s3cr3tvalue") {
		t.Fatalf("url credential leaked: %q", got)
	}
	if !strings.Contains(got, "http://dbuser:***@198.51.100.10:8123") {
		t.Fatalf("url lost its shape: %q", got)
	}
	for _, in := range []string{`http://198.51.100.10:8123/ping`, `mysql://db.internal:3306`} {
		if got := Scrub(in); got != in {
			t.Fatalf("a url without credentials was mangled: %q -> %q", in, got)
		}
	}
}

func TestScrubCoversEnvAssignmentsAndUrlCreds(t *testing.T) {
	got := Scrub(`PGPASSWORD=topsecret /usr/bin/psql`)
	if strings.Contains(got, "topsecret") {
		t.Fatalf("env password leaked: %q", got)
	}
	got = Scrub(`curl https://user:topsecret@example.com/x`)
	if strings.Contains(got, "topsecret") {
		t.Fatalf("url credential leaked: %q", got)
	}
}

func TestScrubCoversPrivateKeyHeaderLines(t *testing.T) {
	got := Scrub(`-----BEGIN RSA PRIVATE KEY----- MIIEowIBAAKCAQEA`)
	if strings.Contains(got, "MIIEowIBAAKCAQEA") {
		t.Fatalf("key material on the header line leaked: %q", got)
	}
}

func TestScrubLeavesOrdinaryCommandLinesUntouched(t *testing.T) {
	for _, in := range []string{
		`/usr/sbin/nginx -g daemon off; master process`,
		`php-fpm: pool app.example.com`,
		`/usr/bin/node /opt/app/server.js --port 3000`,
		`/usr/sbin/mariadbd --basedir=/usr --datadir=/var/lib/mysql`,
	} {
		if got := Scrub(in); got != in {
			t.Fatalf("ordinary command line was altered: %q -> %q", in, got)
		}
	}
}
