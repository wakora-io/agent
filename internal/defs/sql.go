package defs

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/microsoft/go-mssqldb"

	"wakora.io/agent/internal/protocol"
	"wakora.io/agent/internal/secret"
)

type CredResolver func(name string) (secret.Cred, bool)

func runSQL(o *Outcome, service string, p protocol.Probe, timeout time.Duration, resolve CredResolver) {
	o.Check.Target = p.Driver + ":" + p.Query
	cred := secret.Cred{}
	hasSecret := false
	isMSSQL := p.Driver == "sqlserver" || p.Driver == "mssql"
	if p.Secret != "" {
		c, ok := resolve(p.Secret)
		if !ok && !isMSSQL {
			o.Check.Status = "fail"
			o.Check.Error = "secret " + p.Secret + " not set on host (wakora secret set)"
			return
		}
		cred = c
		hasSecret = ok
	} else {
		cred.User = p.User
		if cred.User == "" {
			cred.User = "root"
		}
	}
	dsn, driver, err := buildDSN(p, cred, hasSecret)
	if err != nil {
		o.Check.Status = "fail"
		o.Check.Error = err.Error()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	db, err := sql.Open(driver, dsn)
	if err != nil {
		o.Check.Status = "fail"
		o.Check.Error = err.Error()
		return
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	rows, err := db.QueryContext(ctx, p.Query)
	if err != nil {
		o.Check.Status = "fail"
		o.Check.Error = redact(err.Error(), cred.Pass)
		return
	}
	defer rows.Close()
	o.Check.Status = "ok"

	if len(p.KVMetrics) > 0 {
		kv := scanKV(rows)
		for _, m := range p.KVMetrics {
			if v, ok := parseNum(kv[m.Key]); ok {
				o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: m.Name, Value: v})
			}
		}
		return
	}
	byName := scanRow(rows)
	for _, m := range p.Metrics {
		if v, ok := parseNum(byName[m.Name]); ok {
			o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: "svc." + service + "." + m.Name, Value: v})
		}
	}
}

var mysqlSockets = []string{"/run/mysqld/mysqld.sock", "/var/run/mysqld/mysqld.sock", "/tmp/mysql.sock"}
var pgSocketDirs = []string{"/var/run/postgresql", "/run/postgresql", "/tmp"}

func buildDSN(p protocol.Probe, cred secret.Cred, hasSecret bool) (string, string, error) {
	switch p.Driver {
	case "mysql":
		if p.Socket {
			sock := findSocket(mysqlSockets)
			if sock == "" {
				return "", "", fmt.Errorf("no mysql unix socket found")
			}
			return fmt.Sprintf("%s:%s@unix(%s)/?timeout=5s&readTimeout=5s", cred.User, cred.Pass, sock), "mysql", nil
		}
		addr := p.Address
		if addr == "" {
			addr = "127.0.0.1:3306"
		}
		return fmt.Sprintf("%s:%s@tcp(%s)/?timeout=5s&readTimeout=5s", cred.User, cred.Pass, addr), "mysql", nil
	case "postgres":
		if p.Socket {
			dir := findSocketDir(pgSocketDirs, ".s.PGSQL.5432")
			if dir == "" {
				return "", "", fmt.Errorf("no postgres unix socket found")
			}
			return fmt.Sprintf("postgres://%s:%s@/postgres?host=%s&connect_timeout=5", cred.User, cred.Pass, dir), "pgx", nil
		}
		addr := p.Address
		if addr == "" {
			addr = "127.0.0.1:5432"
		}
		host, port, _ := strings.Cut(addr, ":")
		if port == "" {
			port = "5432"
		}
		return fmt.Sprintf("postgres://%s:%s@%s:%s/postgres?sslmode=disable&connect_timeout=5", cred.User, cred.Pass, host, port), "pgx", nil
	case "sqlserver", "mssql":
		addr := p.Address
		if addr == "" {
			addr = "127.0.0.1:1433"
		}
		host, port, _ := strings.Cut(addr, ":")
		if port == "" {
			port = "1433"
		}
		q := "database=master&connection+timeout=5&encrypt=disable"
		if !hasSecret {
			return fmt.Sprintf("sqlserver://%s:%s?%s", host, port, q), "sqlserver", nil
		}
		return fmt.Sprintf("sqlserver://%s:%s@%s:%s?%s", cred.User, cred.Pass, host, port, q), "sqlserver", nil
	default:
		return "", "", fmt.Errorf("unsupported sql driver %q", p.Driver)
	}
}

func findSocket(paths []string) string {
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil && fi.Mode()&os.ModeSocket != 0 {
			return p
		}
	}
	return ""
}

func findSocketDir(dirs []string, marker string) string {
	for _, d := range dirs {
		if _, err := os.Stat(d + "/" + marker); err == nil {
			return d
		}
	}
	return ""
}

func scanKV(rows *sql.Rows) map[string]string {
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			continue
		}
		out[k] = v
	}
	return out
}

func scanRow(rows *sql.Rows) map[string]string {
	cols, err := rows.Columns()
	if err != nil || !rows.Next() {
		return nil
	}
	cells := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range cells {
		ptrs[i] = &cells[i]
	}
	if err := rows.Scan(ptrs...); err != nil {
		return nil
	}
	out := map[string]string{}
	for i, c := range cols {
		out[c] = asString(cells[i])
	}
	return out
}

func asString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case []byte:
		return string(t)
	case string:
		return t
	default:
		return fmt.Sprintf("%v", t)
	}
}

func parseNum(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	if strings.EqualFold(s, "ON") || strings.EqualFold(s, "YES") {
		return 1, true
	}
	if strings.EqualFold(s, "OFF") || strings.EqualFold(s, "NO") {
		return 0, true
	}
	f, err := strconv.ParseFloat(s, 64)
	return f, err == nil
}

func redact(msg, secret string) string {
	if secret == "" {
		return msg
	}
	return strings.ReplaceAll(msg, secret, "***")
}
