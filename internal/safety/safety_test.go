package safety

import (
	"net"
	"testing"
)

func TestIsPrivateOrLoopback(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"10.255.255.254", true},
		{"172.15.0.1", false},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"172.32.0.1", false},
		{"192.168.1.1", true},
		{"100.64.0.1", true},
		{"100.128.0.1", false},
		{"198.18.0.1", true},
		{"203.0.113.5", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"::1", true},
		{"fc00::1", true},
		{"fd12:3456::1", true},
		{"2001:4860:4860::8888", false},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("parse %q", c.ip)
		}
		if got := IsPrivateOrLoopback(ip); got != c.want {
			t.Errorf("IsPrivateOrLoopback(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestPolicyCheckTarget(t *testing.T) {
	p := DefaultPolicy()
	if err := p.CheckTarget(net.ParseIP("10.0.0.1")); err != nil {
		t.Fatalf("private should be accepted: %v", err)
	}
	if err := p.CheckTarget(net.ParseIP("8.8.8.8")); err == nil {
		t.Fatal("public target should be rejected by default")
	}
	p.AllowPublic = true
	if err := p.CheckTarget(net.ParseIP("8.8.8.8")); err != nil {
		t.Fatalf("public should be accepted with AllowPublic: %v", err)
	}
}

func TestPolicyCheckAuthorized(t *testing.T) {
	p := DefaultPolicy()
	if err := p.CheckAuthorized(); err == nil {
		t.Fatal("unauthorized default should error")
	}
	p.Authorized = true
	if err := p.CheckAuthorized(); err != nil {
		t.Fatalf("authorized policy should pass: %v", err)
	}
}

func TestPolicyNormalise(t *testing.T) {
	p := Policy{MaxWorkers: 100, MaxRatePPS: 1000}
	if got := p.NormaliseWorkers(0); got != 1 {
		t.Errorf("workers floor: got %d", got)
	}
	if got := p.NormaliseWorkers(99999); got != 100 {
		t.Errorf("workers ceiling: got %d", got)
	}
	if got := p.NormaliseRate(0); got != 1000 {
		t.Errorf("rate 0 should clamp to max: got %d", got)
	}
	if got := p.NormaliseRate(500); got != 500 {
		t.Errorf("rate 500 should be unchanged: got %d", got)
	}
	if got := p.NormaliseRate(9999); got != 1000 {
		t.Errorf("rate clamp ceiling: got %d", got)
	}
}
