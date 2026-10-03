package transport

import (
	"context"
	"errors"
	"net"
	"time"
)

var (
	dialPerAddress     = 5 * time.Second
	wsHandshakeTimeout = 30 * time.Second
	lookupAddrs        = net.DefaultResolver.LookupIPAddr
)

func dialEach(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	var ips []net.IPAddr
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IPAddr{{IP: ip}}
	} else if ips, err = lookupAddrs(ctx, host); err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, &net.DNSError{Err: "no addresses", Name: host, IsNotFound: true}
	}
	var errs []error
	for _, ip := range ips {
		d := net.Dialer{Timeout: dialPerAddress, KeepAlive: 30 * time.Second}
		c, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return c, nil
		}
		errs = append(errs, err)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errors.Join(errs...)
}
