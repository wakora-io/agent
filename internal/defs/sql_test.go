package defs

import (
	"testing"

	"wakora.io/agent/internal/protocol"
	"wakora.io/agent/internal/secret"
)

func TestBuildDSNSQLServerIntegrated(t *testing.T) {
	dsn, driver, err := buildDSN(protocol.Probe{Driver: "sqlserver"}, secret.Cred{User: "root"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if driver != "sqlserver" {
		t.Fatalf("driver: %s", driver)
	}
	want := "sqlserver://localhost?connection+timeout=5&database=master&dial+timeout=5&encrypt=disable"
	if dsn != want {
		t.Fatalf("dsn: %s", dsn)
	}
}

func TestBuildDSNSQLServerSecret(t *testing.T) {
	cred := secret.Cred{User: "monitor", Pass: "p@ss/w"}
	dsn, _, err := buildDSN(protocol.Probe{Driver: "sqlserver", Address: "127.0.0.1:1433"}, cred, true)
	if err != nil {
		t.Fatal(err)
	}
	want := "sqlserver://monitor:p%40ss%2Fw@127.0.0.1:1433?connection+timeout=5&database=master&dial+timeout=5&encrypt=disable"
	if dsn != want {
		t.Fatalf("dsn: %s", dsn)
	}
}

func TestBuildDSNSQLServerInstance(t *testing.T) {
	dsn, _, err := buildDSN(protocol.Probe{Driver: "sqlserver", Address: "localhost/SQLEXPRESS"}, secret.Cred{}, false)
	if err != nil {
		t.Fatal(err)
	}
	want := "sqlserver://localhost/SQLEXPRESS?connection+timeout=5&database=master&dial+timeout=5&encrypt=disable"
	if dsn != want {
		t.Fatalf("dsn: %s", dsn)
	}
}

func TestBuildDSNSQLServerSocket(t *testing.T) {
	dsn, _, err := buildDSN(protocol.Probe{Driver: "sqlserver", Socket: true}, secret.Cred{}, false)
	if err != nil {
		t.Fatal(err)
	}
	want := "sqlserver://localhost?connection+timeout=5&database=master&dial+timeout=5&encrypt=disable&protocol=lpc"
	if dsn != want {
		t.Fatalf("dsn: %s", dsn)
	}
}
