// Package attack implements the load generators KillDoSer uses against a
// target. Each Attacker represents a distinct traffic pattern useful for
// exercising different firewall rules:
//
//   - tcp-connect : SYN -> established -> close; stresses conntrack / SYN cookies.
//   - udp-flood   : stateless packet bursts; stresses rate-limit / DPI rules.
//   - http-flood  : real HTTP/1.1 or HTTP/2 requests; stresses L7 policies / WAFs.
//   - slowloris   : slow partial requests; stresses idle-timeout & slow-drip rules.
package attack

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/MKlolbullen/killdoser/internal/metrics"
	"github.com/MKlolbullen/killdoser/internal/target"
)

// Attacker is a single-shot traffic generator. Send performs one logical
// send against ep and records results on m.
type Attacker interface {
	// Name returns a short identifier (used for logging / JSON output).
	Name() string
	// Send executes exactly one attempt.
	Send(ctx context.Context, ep target.Endpoint, m *metrics.Metrics)
}

// Common classifies a send error into a short category used for metrics.
func classify(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "connection refused"):
		return "refused"
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline exceeded"):
		return "timeout"
	case strings.Contains(msg, "no route to host"):
		return "no-route"
	case strings.Contains(msg, "network is unreachable"):
		return "no-network"
	case strings.Contains(msg, "connection reset"):
		return "reset"
	case strings.Contains(msg, "too many open files"):
		return "fd-exhausted"
	case strings.Contains(msg, "tls"):
		return "tls"
	}
	return "other"
}

// TCPConnect dials, writes an optional payload, reads briefly, closes.
type TCPConnect struct {
	Payload []byte
	Timeout time.Duration
	// ReadAfterWrite causes the attacker to attempt a short read so firewalls
	// with stateful inspection see a full request/response exchange.
	ReadAfterWrite bool
}

func (a *TCPConnect) Name() string { return "tcp-connect" }

func (a *TCPConnect) Send(ctx context.Context, ep target.Endpoint, m *metrics.Metrics) {
	m.RecordAttempt()
	dialer := &net.Dialer{Timeout: a.Timeout}
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", ep.String())
	if err != nil {
		m.RecordError(classify(err))
		return
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(a.Timeout))
	n, err := conn.Write(a.Payload)
	if err != nil {
		m.RecordError(classify(err))
		return
	}
	if a.ReadAfterWrite {
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf) // best-effort; don't fail the send on EOF
	}
	m.RecordSuccess(time.Since(start), n)
}

// UDPFlood writes a datagram per Send. UDP is stateless so we re-dial each
// time to let the OS pick a fresh source port (stresses conntrack entries).
type UDPFlood struct {
	Payload []byte
	Timeout time.Duration
}

func (a *UDPFlood) Name() string { return "udp-flood" }

func (a *UDPFlood) Send(ctx context.Context, ep target.Endpoint, m *metrics.Metrics) {
	m.RecordAttempt()
	d := &net.Dialer{Timeout: a.Timeout}
	start := time.Now()
	conn, err := d.DialContext(ctx, "udp", ep.String())
	if err != nil {
		m.RecordError(classify(err))
		return
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(a.Timeout))
	n, err := conn.Write(a.Payload)
	if err != nil {
		m.RecordError(classify(err))
		return
	}
	m.RecordSuccess(time.Since(start), n)
}

// HTTPFlood issues a real HTTP request per Send. Use for exercising L7 rules
// (WAF, path-based policies, method filtering).
type HTTPFlood struct {
	Method   string
	Path     string
	Scheme   string // "http" or "https"
	HostHdr  string // optional override for Host header (empty = ep.Host)
	Headers  map[string]string
	Body     []byte
	UseHTTP2 bool
	Timeout  time.Duration
	Insecure bool // skip TLS verification (lab-only)
}

func (a *HTTPFlood) Name() string {
	if a.UseHTTP2 {
		return "http2-flood"
	}
	return "http-flood"
}

func (a *HTTPFlood) newClient() *http.Client {
	tr := &http.Transport{
		DisableKeepAlives:   true,
		MaxIdleConns:        0,
		TLSHandshakeTimeout: a.Timeout,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: a.Insecure},
		ForceAttemptHTTP2:   a.UseHTTP2,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   a.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (a *HTTPFlood) Send(ctx context.Context, ep target.Endpoint, m *metrics.Metrics) {
	m.RecordAttempt()
	scheme := a.Scheme
	if scheme == "" {
		scheme = "http"
	}
	path := a.Path
	if path == "" {
		path = "/"
	}
	url := fmt.Sprintf("%s://%s%s", scheme, ep.String(), path)

	var body io.Reader
	if len(a.Body) > 0 {
		body = strings.NewReader(string(a.Body))
	}
	method := a.Method
	if method == "" {
		method = "GET"
	}

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		m.RecordError("bad-request")
		return
	}
	hostHdr := a.HostHdr
	if hostHdr == "" {
		hostHdr = ep.Host
	}
	req.Host = hostHdr
	for k, v := range a.Headers {
		req.Header.Set(k, v)
	}
	if _, ok := a.Headers["User-Agent"]; !ok {
		req.Header.Set("User-Agent", "killdoser/2")
	}

	client := a.newClient()
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		m.RecordError(classify(err))
		return
	}
	defer resp.Body.Close()
	n, _ := io.Copy(io.Discard, resp.Body)
	m.RecordSuccess(time.Since(start), len(a.Body)+int(n))
}

// Slowloris holds many partial HTTP requests open, dripping one header line
// every HeaderInterval. Exercises slow-request / idle-timeout firewall rules.
type Slowloris struct {
	Path            string
	HostHdr         string
	HeaderCount     int           // extra headers to drip (default 10)
	HeaderInterval  time.Duration // between drips (default 10s)
	MaxConnDuration time.Duration // cap per-connection lifetime
	DialTimeout     time.Duration
	TLS             bool
	Insecure        bool
}

func (a *Slowloris) Name() string { return "slowloris" }

func (a *Slowloris) Send(ctx context.Context, ep target.Endpoint, m *metrics.Metrics) {
	m.RecordAttempt()
	interval := a.HeaderInterval
	if interval <= 0 {
		interval = 10 * time.Second
	}
	count := a.HeaderCount
	if count <= 0 {
		count = 10
	}
	maxDur := a.MaxConnDuration
	if maxDur <= 0 {
		maxDur = time.Duration(count+2) * interval
	}
	dialer := &net.Dialer{Timeout: a.DialTimeout}
	start := time.Now()

	cctx, cancel := context.WithTimeout(ctx, maxDur)
	defer cancel()

	var conn net.Conn
	var err error
	if a.TLS {
		tlsDialer := &tls.Dialer{NetDialer: dialer, Config: &tls.Config{InsecureSkipVerify: a.Insecure}}
		conn, err = tlsDialer.DialContext(cctx, "tcp", ep.String())
	} else {
		conn, err = dialer.DialContext(cctx, "tcp", ep.String())
	}
	if err != nil {
		m.RecordError(classify(err))
		return
	}
	defer conn.Close()

	host := a.HostHdr
	if host == "" {
		host = ep.Host
	}
	path := a.Path
	if path == "" {
		path = "/"
	}
	preamble := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: killdoser-slow\r\nAccept: */*\r\n", path, host)
	if _, err := conn.Write([]byte(preamble)); err != nil {
		m.RecordError(classify(err))
		return
	}
	sent := len(preamble)

	for i := 0; i < count; i++ {
		select {
		case <-cctx.Done():
			// Time's up / caller cancelled; treat as success — we kept the
			// socket open for the intended duration.
			m.RecordSuccess(time.Since(start), sent)
			return
		case <-time.After(interval):
		}
		line := fmt.Sprintf("X-Slow-%d: drip-%d\r\n", i, i)
		_ = conn.SetWriteDeadline(time.Now().Add(a.DialTimeout))
		n, werr := conn.Write([]byte(line))
		if werr != nil {
			m.RecordError(classify(werr))
			return
		}
		sent += n
	}
	// Finally send the terminating CRLF and close.
	_, _ = conn.Write([]byte("\r\n"))
	m.RecordSuccess(time.Since(start), sent)
}
