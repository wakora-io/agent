package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"wakora.io/agent/internal/buildinfo"
	"wakora.io/agent/internal/secret"
)

type Config struct {
	Endpoint          string
	ServerID          string
	Hostname          string
	Key               string
	Baseline          bool
	CustomMetricsPort int
	Overrides         map[string]map[string]string
	dir               string
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
	c.Baseline = c.Overrides["agent"]["baseline"] == "true"
	if v := c.Overrides["agent"]["custom-metrics-port"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.CustomMetricsPort = n
		}
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

func (c *Config) Dir() string {
	return c.dir
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

func SaveIdentity(dir, serverID, key string) error {
	if dir == "" {
		dir = defaultDir
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	enc, err := secret.Encrypt(key)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "identity")
	return writeINI(path, map[string]map[string]string{"": {"uuid": serverID, "key": enc}})
}

func (c *Config) SaveKey(key string) error {
	if err := SaveIdentity(c.dir, c.ServerID, key); err != nil {
		return err
	}
	c.Key = key
	return nil
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
