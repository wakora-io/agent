package transport

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"wakora.io/agent/internal/protocol"
)

type wsDialer struct {
	keyFn  func() string
	client *http.Client
}

func NewWSDialer(keyFn func() string, certPin string) Dialer {
	return &wsDialer{keyFn: keyFn, client: PinnedClient(certPin)}
}

func PinnedClient(pin string) *http.Client {
	if pin == "" {
		return http.DefaultClient
	}
	want, err := base64.StdEncoding.DecodeString(pin)
	if err != nil {
		want = nil
	}
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			for _, raw := range rawCerts {
				cert, err := x509.ParseCertificate(raw)
				if err != nil {
					continue
				}
				sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
				if want != nil && subtle.ConstantTimeCompare(sum[:], want) == 1 {
					return nil
				}
			}
			return errors.New("transport: certificate pin mismatch")
		},
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
}

func (d *wsDialer) Dial(ctx context.Context, endpoint string) (Conn, error) {
	c, _, err := websocket.Dial(ctx, endpoint, &websocket.DialOptions{
		HTTPClient: d.client,
		HTTPHeader: http.Header{"X-Wakora-Key": {d.keyFn()}},
	})
	if err != nil {
		return nil, err
	}
	c.SetReadLimit(1 << 20)
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
	for {
		_, data, err := w.c.Read(context.Background())
		if err != nil {
			return protocol.Message{}, err
		}
		var m protocol.Message
		if err := json.Unmarshal(data, &m); err != nil {
			continue
		}
		return m, nil
	}
}

func (w *wsConn) Close() error {
	return w.c.Close(websocket.StatusNormalClosure, "")
}
