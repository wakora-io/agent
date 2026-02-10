package transport

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"wakora.io/agent/internal/protocol"
)

type wsDialer struct {
	key string
}

func NewWSDialer(key string) Dialer {
	return &wsDialer{key: key}
}

func (d *wsDialer) Dial(ctx context.Context, endpoint string) (Conn, error) {
	c, _, err := websocket.Dial(ctx, endpoint, &websocket.DialOptions{
		HTTPHeader: http.Header{"X-Wakora-Key": {d.key}},
	})
	if err != nil {
		return nil, err
	}
	return &wsConn{c: c}, nil
}

type wsConn struct {
	c *websocket.Conn
}

func (w *wsConn) Send(m protocol.Message) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return w.c.Write(ctx, websocket.MessageText, data)
}

func (w *wsConn) Recv() (protocol.Message, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_, data, err := w.c.Read(ctx)
	if err != nil {
		return protocol.Message{}, err
	}
	var m protocol.Message
	if err := json.Unmarshal(data, &m); err != nil {
		return protocol.Message{}, err
	}
	return m, nil
}

func (w *wsConn) Close() error {
	return w.c.Close(websocket.StatusNormalClosure, "")
}
