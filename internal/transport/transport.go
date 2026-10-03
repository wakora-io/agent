package transport

import (
	"context"
	"errors"
	"log"
	"math/rand/v2"
	"time"

	"wakora.io/agent/internal/protocol"
)

type Conn interface {
	Send(protocol.Message) error
	Recv() (protocol.Message, error)
	Ping(ctx context.Context) error
	Close() error
}

type Dialer interface {
	Dial(ctx context.Context, endpoint string) (Conn, error)
}

var ErrNoDialer = errors.New("transport: dialer not configured")

var ErrDeregistered = errors.New("transport: deregistered")

var ErrUnauthorized = errors.New("transport: unauthorized")

var ErrKeyRetired = errors.New("transport: key already replaced")

type Client struct {
	Endpoint    string
	Dialer      Dialer
	Backoff     time.Duration
	MaxBackoff  time.Duration
	OnDialError func(error)
}

const (
	defaultMaxBackoff = 30 * time.Second
	stableSession     = time.Minute
)

func nextBackoff(cur, base, ceiling time.Duration) time.Duration {
	if cur < base {
		return base
	}
	cur *= 2
	if cur > ceiling {
		cur = ceiling
	}
	return cur
}

func jittered(d time.Duration) time.Duration {
	if d <= 1 {
		return d
	}
	half := d / 2
	return half + time.Duration(rand.Int64N(int64(d-half)))
}

func (c *Client) Run(ctx context.Context, onConn func(Conn) error) error {
	base := c.Backoff
	if base <= 0 {
		base = time.Second
	}
	ceiling := c.MaxBackoff
	if ceiling <= 0 {
		ceiling = defaultMaxBackoff
	}
	if ceiling < base {
		ceiling = base
	}
	backoff := time.Duration(0)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if c.Dialer == nil {
			return ErrNoDialer
		}
		if conn, err := c.Dialer.Dial(ctx, c.Endpoint); err == nil {
			started := time.Now()
			serr := onConn(conn)
			conn.Close()
			if serr != nil && ctx.Err() == nil {
				log.Printf("connection to %s lost: %v", c.Endpoint, serr)
			}
			if time.Since(started) >= stableSession {
				backoff = 0
			}
		} else if errors.Is(err, ErrDeregistered) {
			if c.OnDialError != nil {
				c.OnDialError(err)
			}
			log.Print("this host was removed from the console; idling. run 'wakora uninstall' to clean up, or 'wakora --key <TEAMKEY>' to re-enroll")
			<-ctx.Done()
			return ctx.Err()
		} else {
			if c.OnDialError != nil {
				c.OnDialError(err)
			}
			log.Printf("dial %s: %v", c.Endpoint, err)
		}
		backoff = nextBackoff(backoff, base, ceiling)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(jittered(backoff)):
		}
	}
}
