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
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
	"wakora.io/agent/internal/buildinfo"
	"wakora.io/agent/internal/protocol"
)

type wsDialer struct {
	keyFn  func() string
	client *http.Client
}

func NewWSDialer(keyFn func() string, certPin string) Dialer {
	return &wsDialer{keyFn: keyFn, client: PinnedClient(certPin)}
}

func decodePin(pin string) ([]byte, error) {
	p := strings.TrimSpace(pin)
	if p == "" {
		return nil, errors.New("transport: certificate pin is empty")
	}
	want, err := base64.StdEncoding.DecodeString(p)
	if err != nil {
		return nil, errors.New("transport: certificate pin is not valid base64")
	}
	if len(want) != sha256.Size {
		return nil, fmt.Errorf("transport: certificate pin is %d bytes, want %d", len(want), sha256.Size)
	}
	return want, nil
}

func PinnedClient(pin string) *http.Client {
	want, err := decodePin(pin)
	if err != nil {
		if buildinfo.Version != "dev" {
			log.Fatalf("%v - refusing to run a release build without certificate pinning", err)
		}
		return http.DefaultClient
	}
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("transport: server presented no certificate")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return errors.New("transport: server leaf certificate is unparsable")
			}
			sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
			if subtle.ConstantTimeCompare(sum[:], want) != 1 {
				return errors.New("transport: certificate pin mismatch")
			}
			return nil
		},
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
}

func (d *wsDialer) Dial(ctx context.Context, endpoint string) (Conn, error) {
	c, resp, err := websocket.Dial(ctx, endpoint, &websocket.DialOptions{
		HTTPClient: d.client,
		HTTPHeader: http.Header{"X-Wakora-Key": {d.keyFn()}},
	})
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusGone {
			return nil, ErrDeregistered
		}
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			return nil, ErrUnauthorized
		}
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

func (w *wsConn) Ping(ctx context.Context) error {
	return w.c.Ping(ctx)
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
