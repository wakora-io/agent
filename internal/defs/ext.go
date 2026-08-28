package defs

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptrace"
	"regexp"
	"strconv"
	"strings"
	"time"

	"wakora.io/agent/internal/protocol"
)

func runExt(o *Outcome, service string, p protocol.Probe, timeout time.Duration) {
	targets := p.Targets
	if len(targets) == 0 && p.URL != "" {
		targets = []string{p.URL}
	}
	if len(targets) == 0 {
		o.Check.Status = "fail"
		o.Check.Error = "no targets listed"
		return
	}
	o.Check.Target = strings.Join(targets, ",")

	var bodyRe *regexp.Regexp
	if p.ExpectBody != "" {
		if re, err := regexp.Compile(p.ExpectBody); err == nil {
			bodyRe = re
		}
	}

	var down []string
	for _, url := range targets {
		r := probeExternal(url, p.ExpectStatus, bodyRe, timeout)
		tags := map[string]string{"url": url}
		up := 0.0
		if r.up {
			up = 1
		}
		o.Metrics = append(o.Metrics,
			protocol.MetricPoint{Name: "ext." + service + ".up", Value: up, Tags: tags},
			protocol.MetricPoint{Name: "ext." + service + ".latency_ms", Value: r.totalMs, Tags: tags},
		)
		if r.status > 0 {
			o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: "ext." + service + ".status", Value: float64(r.status), Tags: tags})
		}
		if r.dnsMs > 0 {
			o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: "ext." + service + ".dns_ms", Value: r.dnsMs, Tags: tags})
		}
		if r.connectMs > 0 {
			o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: "ext." + service + ".connect_ms", Value: r.connectMs, Tags: tags})
		}
		if r.tlsMs > 0 {
			o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: "ext." + service + ".tls_ms", Value: r.tlsMs, Tags: tags})
		}
		if r.ttfbMs > 0 {
			o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: "ext." + service + ".ttfb_ms", Value: r.ttfbMs, Tags: tags})
		}
		invPayload := map[string]any{"status": r.status}
		if r.hasSSL {
			trusted := 0.0
			if r.trusted {
				trusted = 1
			}
			o.Metrics = append(o.Metrics,
				protocol.MetricPoint{Name: "ext." + service + ".ssl_days_left", Value: float64(int(r.sslDays*10)) / 10, Tags: tags},
				protocol.MetricPoint{Name: "ext." + service + ".ssl_trusted", Value: trusted, Tags: tags},
			)
			invPayload["sslExpiry"] = r.sslExpiry.UTC().Format("2006-01-02")
			invPayload["sslTrusted"] = r.trusted
		}
		if bodyRe != nil {
			match := 0.0
			if r.bodyMatch {
				match = 1
			}
			o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: "ext." + service + ".body_match", Value: match, Tags: tags})
		}
		if payload, err := json.Marshal(invPayload); err == nil {
			o.InvFacts = append(o.InvFacts, protocol.Fact{Kind: "external", Key: url, Payload: string(payload)})
		}
		if !r.up {
			down = append(down, url+": "+r.note)
		}
	}
	if len(down) == len(targets) {
		o.Check.Status = "fail"
		o.Check.Error = strings.Join(down, "; ")
		return
	}
	o.Check.Status = "ok"
	if len(down) > 0 {
		o.Check.Error = strings.Join(down, "; ")
	}
}

type extResult struct {
	up                                       bool
	status                                   int
	totalMs, dnsMs, connectMs, tlsMs, ttfbMs float64
	hasSSL, trusted, bodyMatch               bool
	sslDays                                  float64
	sslExpiry                                time.Time
	note                                     string
}

func probeExternal(url string, expectStatus int, bodyRe *regexp.Regexp, timeout time.Duration) extResult {
	var r extResult
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		r.note = err.Error()
		return r
	}
	req.Header.Set("User-Agent", probeUserAgent)

	var dnsStart, connectStart, tlsStart, start time.Time
	trace := &httptrace.ClientTrace{
		DNSStart:             func(httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone:              func(httptrace.DNSDoneInfo) { r.dnsMs = msSince(dnsStart) },
		ConnectStart:         func(_, _ string) { connectStart = time.Now() },
		ConnectDone:          func(_, _ string, _ error) { r.connectMs = msSince(connectStart) },
		TLSHandshakeStart:    func() { tlsStart = time.Now() },
		TLSHandshakeDone:     func(tls.ConnectionState, error) { r.tlsMs = msSince(tlsStart) },
		GotFirstResponseByte: func() { r.ttfbMs = msSince(start) },
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	start = time.Now()
	resp, err := client.Do(req)
	r.totalMs = msSince(start)
	if err != nil {
		r.note = err.Error()
		return r
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	resp.Body.Close()
	r.status = resp.StatusCode

	var notes []string
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		r.hasSSL = true
		cert := resp.TLS.PeerCertificates[0]
		r.sslExpiry = cert.NotAfter
		r.sslDays = time.Until(cert.NotAfter).Hours() / 24
		r.trusted = true
		if time.Now().After(cert.NotAfter) {
			r.trusted = false
			notes = append(notes, "certificate expired")
		} else if note := verifyCert(resp.TLS.PeerCertificates, req.URL.Hostname()); note != "" {
			r.trusted = false
			notes = append(notes, note)
		}
	}

	statusOK := resp.StatusCode < 500
	if expectStatus > 0 {
		statusOK = resp.StatusCode == expectStatus
	}
	if bodyRe != nil {
		r.bodyMatch = bodyRe.Match(body)
	}
	r.up = statusOK && (bodyRe == nil || r.bodyMatch)
	if !statusOK {
		notes = append([]string{"status " + strconv.Itoa(resp.StatusCode)}, notes...)
	} else if resp.StatusCode >= 400 {
		notes = append(notes, "status "+strconv.Itoa(resp.StatusCode))
	}
	if bodyRe != nil && !r.bodyMatch {
		notes = append(notes, "body assertion failed")
	}
	r.note = strings.Join(notes, "; ")
	return r
}

func msSince(t time.Time) float64 {
	if t.IsZero() {
		return 0
	}
	return float64(time.Since(t).Microseconds()) / 1000
}
