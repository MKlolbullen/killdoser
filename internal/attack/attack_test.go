package attack

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MKlolbullen/killdoser/internal/metrics"
	"github.com/MKlolbullen/killdoser/internal/target"
)

func mustEndpoint(t *testing.T, addr string) target.Endpoint {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		t.Fatalf("bad host %q", host)
	}
	ep := target.Endpoint{IP: ip, Host: host}
	_, err = net.LookupPort("tcp", port)
	if err != nil {
		t.Fatal(err)
	}
	// Parse port directly.
	p := 0
	for _, r := range port {
		p = p*10 + int(r-'0')
	}
	ep.Port = p
	return ep
}

func TestTCPConnectSuccess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				buf := make([]byte, 128)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("ok"))
				c.Close()
			}(c)
		}
	}()

	a := &TCPConnect{Payload: []byte("hello"), Timeout: 2 * time.Second, ReadAfterWrite: true}
	m := metrics.New(64)
	a.Send(context.Background(), mustEndpoint(t, ln.Addr().String()), m)
	s := m.Snapshot()
	if s.Successes != 1 {
		t.Fatalf("expected 1 success, got %+v", s)
	}
	if s.BytesSent < 5 {
		t.Fatalf("bytes should include payload: %+v", s)
	}
}

func TestTCPConnectRefused(t *testing.T) {
	// Pick a port by binding then closing; subsequent connects should refuse.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	a := &TCPConnect{Payload: []byte("x"), Timeout: 500 * time.Millisecond}
	m := metrics.New(64)
	a.Send(context.Background(), mustEndpoint(t, addr), m)
	s := m.Snapshot()
	if s.Errors != 1 {
		t.Fatalf("expected 1 error, got %+v", s)
	}
}

func TestHTTPFloodSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello")
	}))
	defer srv.Close()

	// srv.URL is http://127.0.0.1:PORT
	u := srv.URL
	u = strings.TrimPrefix(u, "http://")
	host, port, _ := net.SplitHostPort(u)
	ep := target.Endpoint{IP: net.ParseIP(host), Host: host}
	// Parse port
	for _, r := range port {
		ep.Port = ep.Port*10 + int(r-'0')
	}

	a := &HTTPFlood{Method: "GET", Path: "/", Scheme: "http", Timeout: 2 * time.Second}
	m := metrics.New(64)
	a.Send(context.Background(), ep, m)
	s := m.Snapshot()
	if s.Successes != 1 {
		t.Fatalf("expected 1 success, got %+v", s)
	}
}
