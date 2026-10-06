package transport

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"sync"
	"time"
)

var (
	dialPerAddress     = 5 * time.Second
	wsHandshakeTimeout = 30 * time.Second
	lookupAddrs        = net.DefaultResolver.LookupIPAddr
	avoidFor           = time.Minute
)

type avoidList struct {
	mu    sync.Mutex
	until map[string]time.Time
}

var avoided avoidList

func (a *avoidList) add(ip string, now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.until == nil {
		a.until = map[string]time.Time{}
	}
	a.until[ip] = now.Add(avoidFor)
}

func (a *avoidList) has(ip string, now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	until, ok := a.until[ip]
	if !ok {
		return false
	}
	if !now.Before(until) {
		delete(a.until, ip)
		return false
	}
	return true
}

func (a *avoidList) reset() {
	a.mu.Lock()
	a.until = nil
	a.mu.Unlock()
}

func orderAddrs(ips []net.IPAddr, now time.Time) []net.IPAddr {
	shuffled := append([]net.IPAddr(nil), ips...)
	rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	out := make([]net.IPAddr, 0, len(shuffled))
	var later []net.IPAddr
	for _, ip := range shuffled {
		if avoided.has(ip.IP.String(), now) {
			later = append(later, ip)
			continue
		}
		out = append(out, ip)
	}
	return append(out, later...)
}

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
	for _, ip := range orderAddrs(ips, time.Now()) {
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
