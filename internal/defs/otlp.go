package defs

import (
	"net/url"
	"strconv"
)

var OTLPEnsure func(port int)

func ensureOTLPFor(endpoint string) {
	if OTLPEnsure == nil {
		return
	}
	port, ok := otlpLoopbackPort(endpoint)
	if !ok {
		return
	}
	OTLPEnsure(port)
}

func otlpLoopbackPort(endpoint string) (int, bool) {
	if endpoint == "" {
		return 4318, true
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return 0, false
	}
	host := u.Hostname()
	if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		return 0, false
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil && n > 0 {
			return n, true
		}
		return 0, false
	}
	return 4318, true
}
