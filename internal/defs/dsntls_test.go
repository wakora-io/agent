package defs

import (
	"net/url"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"

	"wakora.io/agent/internal/protocol"
	"wakora.io/agent/internal/secret"
)

func TestLocalTargetsStayPlaintext(t *testing.T) {
	cred := secret.Cred{User: "u", Pass: "p"}
	for _, tc := range []struct {
		driver string
		addr   string
		want   string
	}{
		{"mysql", "", "tls=true"},
		{"mysql", "127.0.0.1:3306", "tls=true"},
		{"mysql", "localhost:3306", "tls=true"},
		{"postgres", "127.0.0.1:5432", "sslmode=verify-full"},
		{"sqlserver", "localhost", "encrypt=true"},
	} {
		dsn, _, err := buildDSN(protocol.Probe{Driver: tc.driver, Address: tc.addr}, cred, true)
		if err != nil {
			t.Fatalf("%s %s: %v", tc.driver, tc.addr, err)
		}
		if strings.Contains(dsn, tc.want) {
			t.Fatalf("%s %s must stay plaintext on loopback, got %q", tc.driver, tc.addr, dsn)
		}
	}
}

func TestRemoteTargetsRequireVerifiedTLS(t *testing.T) {
	cred := secret.Cred{User: "u", Pass: "p"}
	for _, tc := range []struct {
		driver string
		addr   string
		want   string
	}{
		{"mysql", "db.internal:3306", "tls=true"},
		{"postgres", "db.internal:5432", "sslmode=verify-full"},
		{"sqlserver", "db.internal:1433", "encrypt=true"},
	} {
		dsn, _, err := buildDSN(protocol.Probe{Driver: tc.driver, Address: tc.addr}, cred, true)
		if err != nil {
			t.Fatalf("%s: %v", tc.driver, err)
		}
		if !strings.Contains(dsn, tc.want) {
			t.Fatalf("%s to a remote host must ask for verified TLS, got %q", tc.driver, dsn)
		}
	}
}

func TestRemotePlaintextNeedsAnExplicitSignedException(t *testing.T) {
	cred := secret.Cred{User: "u", Pass: "p"}
	dsn, _, err := buildDSN(protocol.Probe{Driver: "postgres", Address: "db.internal:5432", Insecure: true}, cred, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dsn, "sslmode=disable") {
		t.Fatalf("an explicit insecure definition must still be able to connect: %q", dsn)
	}
}

func TestPasswordsWithDelimitersSurviveTheDSN(t *testing.T) {
	cred := secret.Cred{User: "mon@itor", Pass: "p@ss:w/rd?x#1"}
	dsn, _, err := buildDSN(protocol.Probe{Driver: "mysql", Address: "db.internal:3306"}, cred, true)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatalf("mysql dsn does not parse: %v", err)
	}
	if cfg.User != cred.User || cfg.Passwd != cred.Pass || cfg.Addr != "db.internal:3306" {
		t.Fatalf("mysql dsn lost the credential: user=%q pass=%q addr=%q", cfg.User, cfg.Passwd, cfg.Addr)
	}
	dsn, _, err = buildDSN(protocol.Probe{Driver: "postgres", Address: "[2001:db8::5]:5433"}, cred, true)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("postgres dsn does not parse: %v", err)
	}
	pass, _ := u.User.Password()
	if u.User.Username() != cred.User || pass != cred.Pass || u.Hostname() != "2001:db8::5" || u.Port() != "5433" {
		t.Fatalf("postgres dsn lost the credential or the address: %q", dsn)
	}
}

func TestUnixSocketDSNsAreNeverTreatedAsRemote(t *testing.T) {
	if !localTarget("/run/mysqld/mysqld.sock") {
		t.Fatal("a unix socket path is local by construction")
	}
	if localTarget("db.internal:3306") {
		t.Fatal("a hostname is not local")
	}
	if !localTarget("localhost/SQLEXPRESS") {
		t.Fatal("a named instance on localhost is local")
	}
}
