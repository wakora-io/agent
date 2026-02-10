package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

const defaultDir = "/etc/wakora"

type Config struct {
	Endpoint  string            `json:"endpoint"`
	ServerID  string            `json:"serverId"`
	Key       string            `json:"key"`
	UpdateURL string            `json:"updateUrl"`
	Secrets   map[string]string `json:"-"`
	dir       string
}

func Load(dir string) (*Config, error) {
	if dir == "" {
		dir = defaultDir
	}
	c := &Config{dir: dir, Secrets: map[string]string{}}
	if data, err := os.ReadFile(filepath.Join(dir, "config.json")); err == nil {
		_ = json.Unmarshal(data, c)
	}
	if v := os.Getenv("WAKORA_ENDPOINT"); v != "" {
		c.Endpoint = v
	}
	if v := os.Getenv("WAKORA_KEY"); v != "" {
		c.Key = v
	}
	if v := os.Getenv("WAKORA_UPDATE_URL"); v != "" {
		c.UpdateURL = v
	}
	if c.ServerID == "" {
		if h, err := os.Hostname(); err == nil {
			c.ServerID = h
		}
	}
	return c, nil
}

func (c *Config) RingPath() string {
	return filepath.Join(c.dir, "buffer.jsonl")
}
