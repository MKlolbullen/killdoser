package target

import (
	"testing"
)

func TestParseIPWithDefaultPort(t *testing.T) {
	eps, err := Parse(Spec{Raw: "10.0.0.1", DefaultPort: 80})
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 1 || eps[0].Port != 80 || eps[0].IP.String() != "10.0.0.1" {
		t.Fatalf("unexpected endpoints: %+v", eps)
	}
}

func TestParseIPWithInlinePort(t *testing.T) {
	eps, err := Parse(Spec{Raw: "10.0.0.1:8443", DefaultPort: 80})
	if err != nil {
		t.Fatal(err)
	}
	if eps[0].Port != 8443 {
		t.Fatalf("inline port lost: %+v", eps)
	}
}

func TestParseIPv6Bracketed(t *testing.T) {
	eps, err := Parse(Spec{Raw: "[::1]:9000"})
	if err != nil {
		t.Fatal(err)
	}
	if eps[0].Port != 9000 || eps[0].String() != "[::1]:9000" {
		t.Fatalf("ipv6 bracketed: %+v %q", eps, eps[0].String())
	}
}

func TestParseCIDRv4(t *testing.T) {
	eps, err := Parse(Spec{Raw: "192.168.1.0/30", DefaultPort: 22})
	if err != nil {
		t.Fatal(err)
	}
	// /30 -> 4 addresses; /30 keeps both boundary addresses (ones<31 gate trims
	// only when ones < 31, so /30 trims network+broadcast -> 2 hosts).
	if len(eps) != 2 {
		t.Fatalf("expected 2 host endpoints, got %d: %+v", len(eps), eps)
	}
	if eps[0].IP.String() != "192.168.1.1" || eps[1].IP.String() != "192.168.1.2" {
		t.Fatalf("unexpected range: %+v", eps)
	}
}

func TestParseCIDRTooLarge(t *testing.T) {
	_, err := Parse(Spec{Raw: "10.0.0.0/8", DefaultPort: 80})
	if err == nil {
		t.Fatal("expected rejection of oversized CIDR")
	}
}

func TestParseRejectsEmpty(t *testing.T) {
	if _, err := Parse(Spec{Raw: "   "}); err == nil {
		t.Fatal("empty target should error")
	}
}

func TestParseRequiresPortForBareIP(t *testing.T) {
	if _, err := Parse(Spec{Raw: "10.0.0.1"}); err == nil {
		t.Fatal("missing port should error")
	}
}

func TestParseCIDRRequiresPort(t *testing.T) {
	if _, err := Parse(Spec{Raw: "10.0.0.0/30"}); err == nil {
		t.Fatal("CIDR without port should error")
	}
}
