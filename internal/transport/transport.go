package transport

import (
	"context"
	"errors"
	"log"
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
		} else if errors.Is(err, ErrDeregistered) {
			log.Print("this host was removed from the console; idling. run 'wakora uninstall' to clean up, or 'wakora --key <TEAMKEY>' to re-enroll")
			<-ctx.Done()
			return ctx.Err()
		} else {
			log.Printf("dial %s: %v", c.Endpoint, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
	}
}
