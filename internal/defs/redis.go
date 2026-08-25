package defs

import (
	"context"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"wakora.io/agent/internal/protocol"
)

func runRedis(o *Outcome, service string, p protocol.Probe, timeout time.Duration, resolve CredResolver) {
	addr := p.Address
	if addr == "" {
		addr = "127.0.0.1:6379"
	}
	o.Check.Target = "redis:" + addr

	opts := &redis.Options{Addr: addr, DialTimeout: timeout, ReadTimeout: timeout, MaxRetries: -1}
	if p.Secret != "" {
		c, ok := resolve(p.Secret)
		if !ok {
			o.Check.Status = "fail"
			o.Check.Error = "secret " + p.Secret + " not set on host (wakora secret set)"
			return
		}
		if c.User != "" && c.User != "default" {
			opts.Username = c.User
		}
		opts.Password = c.Pass
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	client := redis.NewClient(opts)
	defer client.Close()

	raw, err := client.Info(ctx).Result()
	if err != nil {
		o.Check.Status = "fail"
		o.Check.Error = err.Error()
		return
	}
	o.Check.Status = "ok"

	applyKV(o, p, parseRedisInfo(raw))
}

func parseRedisInfo(raw string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		out[k] = v
	}
	return out
}
