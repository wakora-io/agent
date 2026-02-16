package secret

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Cred struct {
	User string
	Pass string
	Priv string
}

func storePath(dir string) string {
	return filepath.Join(dir, "secrets.conf")
}

func SetCred(dir, name string, c Cred) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	all, err := loadRaw(dir)
	if err != nil {
		return err
	}
	encUser, err := Encrypt(c.User)
	if err != nil {
		return err
	}
	encPass, err := Encrypt(c.Pass)
	if err != nil {
		return err
	}
	fields := map[string]string{"user": encUser, "pass": encPass}
	if c.Priv != "" {
		encPriv, err := Encrypt(c.Priv)
		if err != nil {
			return err
		}
		fields["priv"] = encPriv
	}
	all[name] = fields
	return writeRaw(dir, all)
}

func GetCred(dir, name string) (Cred, bool) {
	all, err := loadRaw(dir)
	if err != nil {
		return Cred{}, false
	}
	fields, ok := all[name]
	if !ok {
		return Cred{}, false
	}
	user, err := Decrypt(fields["user"])
	if err != nil {
		return Cred{}, false
	}
	pass, err := Decrypt(fields["pass"])
	if err != nil {
		return Cred{}, false
	}
	c := Cred{User: user, Pass: pass}
	if enc, ok := fields["priv"]; ok {
		if priv, err := Decrypt(enc); err == nil {
			c.Priv = priv
		}
	}
	return c, true
}

func ListCreds(dir string) []string {
	all, err := loadRaw(dir)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(all))
	for n := range all {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func RemoveCred(dir, name string) (bool, error) {
	all, err := loadRaw(dir)
	if err != nil {
		return false, err
	}
	if _, ok := all[name]; !ok {
		return false, nil
	}
	delete(all, name)
	return true, writeRaw(dir, all)
}

func loadRaw(dir string) (map[string]map[string]string, error) {
	out := map[string]map[string]string{}
	f, err := os.Open(storePath(dir))
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		left := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		dot := strings.LastIndexByte(left, '.')
		if dot < 0 {
			continue
		}
		name, field := left[:dot], left[dot+1:]
		if out[name] == nil {
			out[name] = map[string]string{}
		}
		out[name][field] = val
	}
	return out, nil
}

func writeRaw(dir string, all map[string]map[string]string) error {
	names := make([]string, 0, len(all))
	for n := range all {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		fields := all[n]
		keys := make([]string, 0, len(fields))
		for k := range fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			b.WriteString(n + "." + k + " = " + fields[k] + "\n")
		}
	}
	return os.WriteFile(storePath(dir), []byte(b.String()), 0o600)
}
