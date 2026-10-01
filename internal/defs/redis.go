package defs

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"wakora.io/agent/internal/protocol"
	"wakora.io/agent/internal/secret"
)

func runRedis(o *Outcome, service string, p protocol.Probe, timeout time.Duration, resolve CredResolver) {
	addr := p.Address
	if addr == "" {
		addr = "127.0.0.1:6379"
	}
	o.Check.Target = "redis:" + addr

	opts := &redis.Options{Addr: addr, DialTimeout: timeout, ReadTimeout: timeout, MaxRetries: -1}
	if !localTarget(addr) && !p.Insecure {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		opts.TLSConfig = &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	}
	var cred secret.Cred
	hasCred := false
	optionalUnset := false
	if p.Secret != "" {
		c, ok := resolve(p.Secret)
		if !ok {
			o.Check.Status = "fail"
			o.Check.Error = secret.MissingOr(p.Secret, "secret "+p.Secret+" not set on host (wakora secret set)")
			return
		}
		cred = c
		hasCred = true
	} else if p.SecretOpt != "" {
		if c, ok := resolve(p.SecretOpt); ok {
			cred = c
			hasCred = true
		} else {
			optionalUnset = true
		}
	}
	if hasCred {
		if cred.User != "" && cred.User != "default" {
			opts.Username = cred.User
		}
		opts.Password = cred.Pass
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	client := redis.NewClient(opts)
	defer client.Close()

	raw, err := client.Info(ctx).Result()
	if err != nil {
		o.Check.Status = "fail"
		o.Check.Error = err.Error()
		if optionalUnset && redisAuthRequired(err) {
			o.Check.Error += " - set a monitoring credential: wakora secret set " + p.SecretOpt
		}
		return
	}
	o.Check.Status = "ok"

	applyKV(o, p, parseRedisInfo(raw))
}

func redisAuthRequired(err error) bool {
	s := err.Error()
	return strings.Contains(s, "NOAUTH") || strings.Contains(s, "WRONGPASS")
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
