package defs

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"

	"wakora.io/agent/internal/protocol"
	"wakora.io/agent/internal/secret"
)

type CredResolver func(name string) (secret.Cred, bool)

func runSQL(o *Outcome, service string, p protocol.Probe, timeout time.Duration, resolve CredResolver) {
	o.Check.Target = p.Driver + ":" + p.Query
	cred := secret.Cred{}
	if p.Secret != "" {
		c, ok := resolve(p.Secret)
		if !ok {
			o.Check.Status = "fail"
			o.Check.Error = "secret " + p.Secret + " not set on host (wakora secret set)"
			return
		}
		cred = c
	}
	dsn, driver, err := buildDSN(p, cred)
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

func buildDSN(p protocol.Probe, cred secret.Cred) (string, string, error) {
	addr := p.Address
	switch p.Driver {
	case "mysql":
		if addr == "" {
			addr = "127.0.0.1:3306"
		}
		return fmt.Sprintf("%s:%s@tcp(%s)/?timeout=5s&readTimeout=5s", cred.User, cred.Pass, addr), "mysql", nil
	case "postgres":
		if addr == "" {
			addr = "127.0.0.1:5432"
		}
		host, port, _ := strings.Cut(addr, ":")
		if port == "" {
			port = "5432"
		}
		return fmt.Sprintf("postgres://%s:%s@%s:%s/postgres?sslmode=disable&connect_timeout=5", cred.User, cred.Pass, host, port), "pgx", nil
	default:
		return "", "", fmt.Errorf("unsupported sql driver %q", p.Driver)
	}
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
