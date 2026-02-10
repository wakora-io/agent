package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

const defaultDir = "/etc/wakora"

type Config struct {
	Endpoint string            `json:"endpoint"`
	ServerID string            `json:"serverId"`
	Secrets  map[string]string `json:"-"`
	dir      string
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
	return c, nil
}

func (c *Config) RingPath() string {
	return filepath.Join(c.dir, "buffer.jsonl")
}
