// Package target parses and enumerates test targets.
//
// A Spec describes what the operator typed ("10.0.0.0/24", "example.lab",
// "198.51.100.5:8080") and a Resolved set is what the rest of the tool
// actually hits. Domains are resolved once up-front so that test runs do not
// hammer the resolver.
package target

import (
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
)

// Spec is the operator-supplied target description plus default port.
type Spec struct {
	Raw         string
	DefaultPort int
}

// Endpoint is a concrete host:port we will dial.
type Endpoint struct {
	IP   net.IP
	Host string // original hostname when a domain was supplied, else ip string
	Port int
}

// String returns the host:port form suitable for net.Dial.
func (e Endpoint) String() string {
	host := e.IP.String()
	if e.IP.To4() == nil { // IPv6 needs brackets
		host = "[" + host + "]"
	}
	return host + ":" + strconv.Itoa(e.Port)
}

// Parse resolves a spec into one or more endpoints.
//
// Supported inputs:
//   - host  (domain or IP)  -> uses DefaultPort
//   - host:port             -> overrides DefaultPort
//   - CIDR (IPv4 or IPv6)   -> enumerates every host in the block
//
// CIDR blocks larger than /20 (IPv4) or /116 (IPv6) are rejected to avoid
// accidentally producing millions of endpoints.
func Parse(spec Spec) ([]Endpoint, error) {
	raw := strings.TrimSpace(spec.Raw)
	if raw == "" {
		return nil, fmt.Errorf("empty target")
	}

	if strings.Contains(raw, "/") {
		return parseCIDR(raw, spec.DefaultPort)
	}

	host, port, err := splitHostPort(raw, spec.DefaultPort)
	if err != nil {
		return nil, err
	}

	if ip := net.ParseIP(host); ip != nil {
		return []Endpoint{{IP: ip, Host: ip.String(), Port: port}}, nil
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("resolve %q: no addresses", host)
	}
	out := make([]Endpoint, 0, len(ips))
	for _, ip := range ips {
		out = append(out, Endpoint{IP: ip, Host: host, Port: port})
	}
	return out, nil
}

func splitHostPort(raw string, defaultPort int) (string, int, error) {
	// Bracketed IPv6 with port: [::1]:80
	if strings.HasPrefix(raw, "[") {
		host, portStr, err := net.SplitHostPort(raw)
		if err != nil {
			return "", 0, fmt.Errorf("parse %q: %w", raw, err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return "", 0, fmt.Errorf("parse port in %q: %w", raw, err)
		}
		return host, port, nil
	}
	// Bare IPv6 like ::1 contains colons but no port.
	if ip := net.ParseIP(raw); ip != nil {
		if defaultPort == 0 {
			return "", 0, fmt.Errorf("no port supplied for %q", raw)
		}
		return raw, defaultPort, nil
	}
	if strings.Count(raw, ":") == 1 {
		host, portStr, err := net.SplitHostPort(raw)
		if err != nil {
			return "", 0, fmt.Errorf("parse %q: %w", raw, err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return "", 0, fmt.Errorf("parse port in %q: %w", raw, err)
		}
		return host, port, nil
	}
	if defaultPort == 0 {
		return "", 0, fmt.Errorf("no port supplied for %q", raw)
	}
	return raw, defaultPort, nil
}

// maxCIDRHosts is the ceiling we enforce to prevent absurd enumerations.
const maxCIDRHosts = 1 << 12 // 4096

func parseCIDR(raw string, port int) ([]Endpoint, error) {
	if port == 0 {
		return nil, fmt.Errorf("CIDR target %q requires --port", raw)
	}
	ip, ipnet, err := net.ParseCIDR(raw)
	if err != nil {
		return nil, fmt.Errorf("parse CIDR %q: %w", raw, err)
	}
	ones, bits := ipnet.Mask.Size()
	hosts := new(big.Int).Lsh(big.NewInt(1), uint(bits-ones))
	if hosts.Cmp(big.NewInt(int64(maxCIDRHosts))) > 0 {
		return nil, fmt.Errorf(
			"CIDR %q would expand to %s endpoints; max is %d. Split the test",
			raw, hosts.String(), maxCIDRHosts,
		)
	}

	var out []Endpoint
	for cur := ip.Mask(ipnet.Mask); ipnet.Contains(cur); inc(cur) {
		ipCopy := make(net.IP, len(cur))
		copy(ipCopy, cur)
		out = append(out, Endpoint{IP: ipCopy, Host: ipCopy.String(), Port: port})
	}
	// For IPv4 /31 and /32 keep all; for broader blocks drop network & broadcast.
	if bits == 32 && ones < 31 && len(out) > 2 {
		out = out[1 : len(out)-1]
	}
	return out, nil
}

func inc(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			return
		}
	}
}
