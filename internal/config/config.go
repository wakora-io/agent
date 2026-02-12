package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"wakora.io/agent/internal/buildinfo"
	"wakora.io/agent/internal/secret"
)

const defaultDir = "/etc/wakora"

type Config struct {
	Endpoint  string
	ServerID  string
	Hostname  string
	Key       string
	Overrides map[string]map[string]string
	dir       string
}

func Load(dir string) (*Config, error) {
	if dir == "" {
		dir = defaultDir
	}
	c := &Config{dir: dir, Endpoint: buildinfo.Endpoint, Overrides: map[string]map[string]string{}}
	if h, err := os.Hostname(); err == nil {
		c.Hostname = h
	}
	if f, err := os.Open(filepath.Join(dir, "wakora.conf")); err == nil {
		c.Overrides = parseINI(f)
		f.Close()
	}
	id, err := loadIdentity(dir)
	if err != nil {
		return nil, err
	}
	c.ServerID = id.uuid
	c.Key = id.key
	return c, nil
}

func (c *Config) RingPath() string {
	return filepath.Join(c.dir, "buffer.jsonl")
}

type identity struct {
	uuid string
	key  string
}

func loadIdentity(dir string) (identity, error) {
	var id identity
	f, err := os.Open(filepath.Join(dir, "identity"))
	if err != nil {
		return id, nil
	}
	defer f.Close()
	vals := parseINI(f)[""]
	id.uuid = vals["uuid"]
	if enc := vals["key"]; enc != "" {
		plain, err := secret.Decrypt(enc)
		if err != nil {
			return id, fmt.Errorf("identity key is not decryptable on this machine: %w", err)
		}
		id.key = plain
	}
	return id, nil
}

func SetKey(dir, key string) (string, error) {
	if dir == "" {
		dir = defaultDir
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	id, _ := loadIdentity(dir)
	if id.uuid == "" {
		u, err := newUUID()
		if err != nil {
			return "", err
		}
		id.uuid = u
	}
	enc, err := secret.Encrypt(key)
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "identity")
	if err := writeINI(path, map[string]map[string]string{"": {"uuid": id.uuid, "key": enc}}); err != nil {
		return "", err
	}
	return id.uuid, nil
}

func WriteOverride(dir, service, key, value string) error {
	if dir == "" {
		dir = defaultDir
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(dir, "wakora.conf")
	sections := map[string]map[string]string{}
	if f, err := os.Open(path); err == nil {
		sections = parseINI(f)
		f.Close()
	}
	if sections[service] == nil {
		sections[service] = map[string]string{}
	}
	sections[service][key] = value
	return writeINI(path, sections)
}

func newUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	s := hex.EncodeToString(b)
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:], nil
}
