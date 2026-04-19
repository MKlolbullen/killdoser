// Package safety enforces authorization and target restrictions.
//
// KillDoSer is intended for authorized testing of firewalls and services in
// controlled lab environments. This package centralises the checks that keep
// it that way: an explicit authorization flag, a default-on private/loopback
// allowlist, and caps that prevent a careless invocation from turning into a
// real-world incident.
package safety

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// ErrNoAuthorization is returned when the caller has not explicitly asserted
// that they are authorized to run the test.
var ErrNoAuthorization = errors.New(
	"authorization required: pass --i-have-authorization or answer the interactive prompts",
)

// AuthorizationNotice is printed before any test begins.
const AuthorizationNotice = `
KillDoSer is a firewall/service stress-testing harness.

By proceeding you assert that:
  * You own the target, or have explicit written authorization to test it.
  * The target is in a sandbox or lab environment you control, or the owner
    has authorized this specific test window.
  * You accept full responsibility for the traffic this tool generates.

Unauthorized use against third-party systems is illegal in most jurisdictions.
`

// Policy describes which targets are acceptable for this run.
type Policy struct {
	// AllowPublic permits targets outside RFC1918/loopback/link-local ranges.
	// Default false — the tool refuses public IPs unless the operator opts in.
	AllowPublic bool

	// Authorized must be true for any test to run.
	Authorized bool

	// MaxWorkers caps concurrency regardless of user input.
	MaxWorkers int

	// MaxRatePPS caps the requested packets-per-second. 0 means unlimited
	// (discouraged; only meaningful in a closed lab).
	MaxRatePPS int
}

// DefaultPolicy returns conservative defaults suitable for lab use.
func DefaultPolicy() Policy {
	return Policy{
		AllowPublic: false,
		Authorized:  false,
		MaxWorkers:  1024,
		MaxRatePPS:  200_000,
	}
}

// CheckAuthorized returns ErrNoAuthorization if the operator has not asserted
// authorization.
func (p Policy) CheckAuthorized() error {
	if !p.Authorized {
		return ErrNoAuthorization
	}
	return nil
}

// CheckTarget validates that the given IP is acceptable under the policy.
func (p Policy) CheckTarget(ip net.IP) error {
	if ip == nil {
		return errors.New("nil target IP")
	}
	if IsPrivateOrLoopback(ip) {
		return nil
	}
	if !p.AllowPublic {
		return fmt.Errorf(
			"target %s is not private/loopback; pass --allow-public to override (only if you have authorization)",
			ip.String(),
		)
	}
	return nil
}

// IsPrivateOrLoopback reports whether ip is in a range considered safe for
// default testing: RFC1918, loopback, link-local, unique-local IPv6, or
// documentation ranges.
func IsPrivateOrLoopback(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		// RFC1918 and CGNAT and TEST-NET ranges.
		switch {
		case ip4[0] == 10:
			return true
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return true
		case ip4[0] == 192 && ip4[1] == 168:
			return true
		case ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127: // CGNAT
			return true
		case ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 2: // TEST-NET-1
			return true
		case ip4[0] == 198 && (ip4[1] == 51 && ip4[2] == 100): // TEST-NET-2
			return true
		case ip4[0] == 203 && ip4[1] == 0 && ip4[2] == 113: // TEST-NET-3
			return true
		case ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19): // benchmark
			return true
		}
		return false
	}
	// IPv6 ULA fc00::/7
	if len(ip) == net.IPv6len && (ip[0]&0xfe) == 0xfc {
		return true
	}
	return false
}

// NormaliseWorkers clamps a requested worker count to the policy maximum.
func (p Policy) NormaliseWorkers(requested int) int {
	if requested < 1 {
		requested = 1
	}
	if p.MaxWorkers > 0 && requested > p.MaxWorkers {
		return p.MaxWorkers
	}
	return requested
}

// NormaliseRate clamps a requested rate (pps) to the policy maximum. A
// requested rate of 0 is interpreted as "unlimited" and clamped to MaxRatePPS.
func (p Policy) NormaliseRate(requested int) int {
	if requested < 0 {
		requested = 0
	}
	if p.MaxRatePPS <= 0 {
		return requested
	}
	if requested == 0 || requested > p.MaxRatePPS {
		return p.MaxRatePPS
	}
	return requested
}

// TrimOrigin is a small helper used when logging to avoid printing trailing
// whitespace copied from interactive prompts.
func TrimOrigin(s string) string { return strings.TrimSpace(s) }
