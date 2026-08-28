package defs

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/microsoft/go-mssqldb"
	_ "github.com/microsoft/go-mssqldb/namedpipe"
	_ "github.com/microsoft/go-mssqldb/sharedmemory"

	"wakora.io/agent/internal/protocol"
	"wakora.io/agent/internal/secret"
)

type CredResolver func(name string) (secret.Cred, bool)

func runSQL(o *Outcome, service string, p protocol.Probe, timeout time.Duration, resolve CredResolver) {
	o.Check.Target = p.Driver + ":" + p.Query
	cred := secret.Cred{}
	hasSecret := false
	optionalUnset := false
	if p.Secret != "" {
		c, ok := resolve(p.Secret)
		if !ok {
			o.Check.Status = "fail"
			o.Check.Error = "secret " + p.Secret + " not set on host (wakora secret set)"
			return
		}
		cred = c
		hasSecret = true
	} else if p.SecretOpt != "" {
		if c, ok := resolve(p.SecretOpt); ok {
			cred = c
			hasSecret = true
		} else {
			optionalUnset = true
		}
	}
	if !hasSecret {
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
		o.Check.Error = redactSecret(err.Error(), cred.Pass)
		if optionalUnset && strings.Contains(o.Check.Error, "Access denied") {
			o.Check.Error += " - set a read-only monitoring credential: wakora secret set " + p.SecretOpt
		}
		return
	}
	defer rows.Close()
	o.Check.Status = "ok"

	if len(p.KVMetrics) > 0 || len(p.KVFacts) > 0 || len(p.KVRatios) > 0 {
		applyKV(o, p, scanKV(rows))
		return
	}
	byName := scanRow(rows)
	for _, m := range p.Metrics {
		if v, ok := parseNum(byName[m.Name]); ok {
			o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: "svc." + service + "." + m.Name, Value: v})
		}
	}
	for _, f := range p.Facts {
		v := strings.TrimSpace(byName[f.Name])
		if f.Regex != "" {
			if m, ok := extract([]byte(v), f.Regex); ok {
				v = m
			} else {
				v = ""
			}
		}
		if v == "" {
			continue
		}
		if o.Facts == nil {
			o.Facts = map[string]string{}
		}
		o.Facts[f.Name] = v
	}
}

func applyKV(o *Outcome, p protocol.Probe, kv map[string]string) {
	for _, m := range p.KVMetrics {
		if v, ok := parseNum(kv[m.Key]); ok {
			o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: m.Name, Value: v})
		}
	}
	for _, r := range p.KVRatios {
		num, okN := parseNum(kv[r.Num])
		den, okD := parseNum(kv[r.Den])
		if okN && okD && den > 0 {
			scale := r.Scale
			if scale == 0 {
				scale = 1
			}
			o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: r.Name, Value: num / den * scale})
		}
	}
	for _, f := range p.KVFacts {
		v := strings.TrimSpace(kv[f.Key])
		if v == "" {
			continue
		}
		if o.Facts == nil {
			o.Facts = map[string]string{}
		}
		o.Facts[f.Name] = v
	}
}

func localTarget(addr string) bool {
	if addr == "" || strings.HasPrefix(addr, "/") {
		return true
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	host, _, _ = strings.Cut(host, "/")
	if strings.EqualFold(host, "localhost") || host == "" || strings.EqualFold(host, ".") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
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
		tlsParam := ""
		if !localTarget(addr) && !p.Insecure {
			tlsParam = "&tls=true"
		}
		return fmt.Sprintf("%s:%s@tcp(%s)/?timeout=5s&readTimeout=5s%s", cred.User, cred.Pass, addr, tlsParam), "mysql", nil
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
		sslMode := "disable"
		if !localTarget(addr) && !p.Insecure {
			sslMode = "verify-full"
		}
		return fmt.Sprintf("postgres://%s:%s@%s:%s/postgres?sslmode=%s&connect_timeout=5", cred.User, cred.Pass, host, port, sslMode), "pgx", nil
	case "sqlserver", "mssql":
		addr := p.Address
		if addr == "" {
			addr = "localhost"
		}
		hostport, instance, _ := strings.Cut(addr, "/")
		q := url.Values{}
		q.Set("database", "master")
		q.Set("connection timeout", "5")
		q.Set("dial timeout", "5")
		if localTarget(hostport) || p.Insecure || p.Socket {
			q.Set("encrypt", "disable")
		} else {
			q.Set("encrypt", "true")
		}
		if p.Socket {
			q.Set("protocol", "lpc")
		}
		u := &url.URL{
			Scheme:   "sqlserver",
			Host:     hostport,
			Path:     instance,
			RawQuery: q.Encode(),
		}
		if hasSecret {
			u.User = url.UserPassword(cred.User, cred.Pass)
		}
		return u.String(), "sqlserver", nil
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

func redactSecret(msg, secret string) string {
	if secret == "" {
		return msg
	}
	return strings.ReplaceAll(msg, secret, "***")
}
