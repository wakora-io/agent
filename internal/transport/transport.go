package transport

import (
	"context"
	"errors"
	"time"

	"wakora.io/agent/internal/protocol"
)

type Conn interface {
	Send(protocol.Message) error
	Recv() (protocol.Message, error)
	Close() error
}

type Dialer interface {
	Dial(ctx context.Context, endpoint string) (Conn, error)
}

var ErrNoDialer = errors.New("transport: dialer not configured")

type Client struct {
	Endpoint string
	Dialer   Dialer
	Backoff  time.Duration
}

func (c *Client) Run(ctx context.Context, onConn func(Conn) error) error {
	backoff := c.Backoff
	if backoff <= 0 {
		backoff = time.Second
	}
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if c.Dialer == nil {
			return ErrNoDialer
		}
		if conn, err := c.Dialer.Dial(ctx, c.Endpoint); err == nil {
			_ = onConn(conn)
			conn.Close()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
	}
}
