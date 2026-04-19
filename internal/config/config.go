// Package config parses command-line flags and (optionally) an interactive
// wizard, producing a Config that the runner consumes.
package config

import (
	"bufio"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Mode enumerates available attack strategies.
type Mode string

const (
	ModeTCP       Mode = "tcp-connect"
	ModeUDP       Mode = "udp-flood"
	ModeHTTP      Mode = "http-flood"
	ModeSlowloris Mode = "slowloris"
)

// Encoding enumerates payload encodings.
type Encoding string

const (
	EncodeNone    Encoding = "none"
	EncodeURL     Encoding = "url"
	EncodeHTML    Encoding = "html"
	EncodeBase64  Encoding = "base64"
	EncodeUnicode Encoding = "unicode"
)

// Config describes a single test run.
type Config struct {
	Mode      Mode
	Target    string
	Port      int
	Payload   string
	Encoding  Encoding

	Workers       int
	RatePPS       int
	Duration      time.Duration
	Count         uint64
	Timeout       time.Duration

	HTTPMethod     string
	HTTPPath       string
	HTTPScheme     string // http or https
	HTTPHostHeader string
	HTTPUseH2      bool
	HTTPInsecure   bool

	SlowHeaders  int
	SlowInterval time.Duration

	Authorized  bool
	AllowPublic bool

	JSONOutput  bool
	Quiet       bool
	Interactive bool
}

// Defaults returns a Config populated with sensible defaults.
func Defaults() Config {
	return Config{
		Mode:         ModeTCP,
		Workers:      64,
		RatePPS:      1000,
		Duration:     30 * time.Second,
		Timeout:      3 * time.Second,
		Encoding:     EncodeNone,
		HTTPMethod:   "GET",
		HTTPPath:     "/",
		HTTPScheme:   "http",
		SlowHeaders:  10,
		SlowInterval: 10 * time.Second,
	}
}

// ParseFlags parses argv; on empty argv it returns defaults.Interactive=true.
func ParseFlags(args []string) (Config, error) {
	cfg := Defaults()

	fs := flag.NewFlagSet("killdoser", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // we print our own usage

	fs.Func("mode", "attack mode (tcp-connect|udp-flood|http-flood|slowloris)", func(v string) error {
		m := Mode(v)
		switch m {
		case ModeTCP, ModeUDP, ModeHTTP, ModeSlowloris:
			cfg.Mode = m
			return nil
		}
		return fmt.Errorf("unknown mode %q", v)
	})
	fs.StringVar(&cfg.Target, "target", "", "target host / IP / CIDR (e.g. 10.0.0.5, lab.example:8080, 192.168.1.0/28)")
	fs.IntVar(&cfg.Port, "port", 0, "default port when target has none")
	fs.StringVar(&cfg.Payload, "payload", "", "raw payload (TCP/UDP modes) or HTTP body")
	fs.Func("encoding", "payload encoding (none|url|html|base64|unicode)", func(v string) error {
		switch Encoding(v) {
		case EncodeNone, EncodeURL, EncodeHTML, EncodeBase64, EncodeUnicode:
			cfg.Encoding = Encoding(v)
			return nil
		}
		return fmt.Errorf("unknown encoding %q", v)
	})

	fs.IntVar(&cfg.Workers, "workers", cfg.Workers, "concurrent workers")
	fs.IntVar(&cfg.RatePPS, "rate", cfg.RatePPS, "target sends per second (0=unlimited up to policy cap)")
	fs.DurationVar(&cfg.Duration, "duration", cfg.Duration, "stop after this wall-clock duration (0=unlimited)")
	fs.Uint64Var(&cfg.Count, "count", 0, "stop after this many sends (0=unlimited)")
	fs.DurationVar(&cfg.Timeout, "timeout", cfg.Timeout, "per-connection timeout")

	fs.StringVar(&cfg.HTTPMethod, "http-method", cfg.HTTPMethod, "HTTP method")
	fs.StringVar(&cfg.HTTPPath, "http-path", cfg.HTTPPath, "HTTP request path")
	fs.StringVar(&cfg.HTTPScheme, "http-scheme", cfg.HTTPScheme, "http or https")
	fs.StringVar(&cfg.HTTPHostHeader, "http-host", "", "override Host header")
	fs.BoolVar(&cfg.HTTPUseH2, "http2", false, "use HTTP/2 for http-flood")
	fs.BoolVar(&cfg.HTTPInsecure, "insecure", false, "skip TLS verification (lab only)")

	fs.IntVar(&cfg.SlowHeaders, "slow-headers", cfg.SlowHeaders, "slowloris: number of dripped headers")
	fs.DurationVar(&cfg.SlowInterval, "slow-interval", cfg.SlowInterval, "slowloris: interval between header drips")

	fs.BoolVar(&cfg.Authorized, "i-have-authorization", false, "assert you are authorized to run this test")
	fs.BoolVar(&cfg.AllowPublic, "allow-public", false, "permit targets outside RFC1918/loopback (requires authorization)")

	fs.BoolVar(&cfg.JSONOutput, "json", false, "emit final summary as JSON")
	fs.BoolVar(&cfg.Quiet, "quiet", false, "suppress periodic progress lines")
	fs.BoolVar(&cfg.Interactive, "interactive", false, "force interactive mode")

	var help bool
	fs.BoolVar(&help, "h", false, "show help")
	fs.BoolVar(&help, "help", false, "show help")

	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if help {
		return cfg, flag.ErrHelp
	}
	if len(args) == 0 {
		cfg.Interactive = true
	}
	return cfg, nil
}

// Usage prints a concise flag reference to w.
func Usage(w io.Writer) {
	fmt.Fprintln(w, `killdoser — firewall / service stress-testing harness

Usage:
  killdoser --target HOST [flags]
  killdoser --interactive                        # guided prompts

Core flags:
  --mode=MODE           tcp-connect | udp-flood | http-flood | slowloris
  --target=HOST         host, host:port, IP, or CIDR
  --port=N              default port (when target has none)
  --payload=STR         bytes to send (TCP/UDP) or HTTP body
  --encoding=ENC        none|url|html|base64|unicode
  --workers=N           concurrent workers                    (default 64)
  --rate=PPS            target sends per second, 0=unlimited  (default 1000)
  --duration=DUR        stop after this duration              (default 30s)
  --count=N             stop after this many sends
  --timeout=DUR         per-op timeout                        (default 3s)

HTTP-mode flags:
  --http-method, --http-path, --http-scheme, --http-host
  --http2, --insecure

Slowloris flags:
  --slow-headers=N, --slow-interval=DUR

Safety:
  --i-have-authorization    required; asserts you're authorized
  --allow-public            permit public-IP targets (lab only)

Output:
  --json                    emit summary as JSON
  --quiet                   suppress progress output
  --interactive             force guided mode
  -h, --help                this message`)
}

// ApplyEncoding transforms cfg.Payload in place according to cfg.Encoding.
func (c *Config) ApplyEncoding() error {
	switch c.Encoding {
	case EncodeNone, "":
		return nil
	case EncodeURL:
		c.Payload = url.QueryEscape(c.Payload)
	case EncodeHTML:
		c.Payload = html.EscapeString(c.Payload)
	case EncodeBase64:
		c.Payload = base64.StdEncoding.EncodeToString([]byte(c.Payload))
	case EncodeUnicode:
		var b strings.Builder
		for _, r := range c.Payload {
			fmt.Fprintf(&b, "\\u%04x", r)
		}
		c.Payload = b.String()
	default:
		return fmt.Errorf("unknown encoding %q", c.Encoding)
	}
	return nil
}

// Validate returns an error if required fields are missing or contradictory.
func (c *Config) Validate() error {
	if c.Target == "" {
		return errors.New("--target is required")
	}
	switch c.Mode {
	case ModeTCP, ModeUDP, ModeHTTP, ModeSlowloris:
	default:
		return fmt.Errorf("invalid --mode %q", c.Mode)
	}
	if c.Workers < 1 {
		return errors.New("--workers must be >= 1")
	}
	if c.Duration == 0 && c.Count == 0 {
		return errors.New("must set --duration and/or --count (to guarantee termination)")
	}
	if c.Mode == ModeHTTP && c.HTTPScheme != "http" && c.HTTPScheme != "https" {
		return fmt.Errorf("--http-scheme must be http or https, got %q", c.HTTPScheme)
	}
	return nil
}

// Wizard walks the operator through an interactive setup and returns a
// populated Config. It is a direct replacement for the original tool's
// prompts, kept for backward compatibility.
func Wizard(in io.Reader, out io.Writer) (Config, error) {
	cfg := Defaults()
	r := bufio.NewReader(in)

	ask := func(prompt string) (string, error) {
		fmt.Fprint(out, prompt)
		line, err := r.ReadString('\n')
		if err != nil && line == "" {
			return "", err
		}
		return strings.TrimSpace(line), nil
	}

	fmt.Fprintln(out, "=== KillDoSer interactive setup ===")

	mode, err := ask("Mode [1=tcp-connect 2=udp-flood 3=http-flood 4=slowloris] (1): ")
	if err != nil {
		return cfg, err
	}
	switch mode {
	case "", "1":
		cfg.Mode = ModeTCP
	case "2":
		cfg.Mode = ModeUDP
	case "3":
		cfg.Mode = ModeHTTP
	case "4":
		cfg.Mode = ModeSlowloris
	default:
		return cfg, fmt.Errorf("invalid mode %q", mode)
	}

	cfg.Target, err = ask("Target (host, host:port, IP, or CIDR): ")
	if err != nil {
		return cfg, err
	}

	portStr, _ := ask("Default port [80]: ")
	if portStr == "" {
		portStr = "80"
	}
	cfg.Port, err = strconv.Atoi(portStr)
	if err != nil || cfg.Port < 1 || cfg.Port > 65535 {
		return cfg, fmt.Errorf("invalid port %q", portStr)
	}

	cfg.Payload, _ = ask("Payload (optional): ")

	enc, _ := ask("Encoding [none|url|html|base64|unicode] (none): ")
	if enc == "" {
		enc = "none"
	}
	cfg.Encoding = Encoding(enc)

	w, _ := ask("Workers [64]: ")
	if w != "" {
		cfg.Workers, _ = strconv.Atoi(w)
	}
	rate, _ := ask("Rate pps [1000]: ")
	if rate != "" {
		cfg.RatePPS, _ = strconv.Atoi(rate)
	}
	dur, _ := ask("Duration [30s]: ")
	if dur != "" {
		cfg.Duration, err = time.ParseDuration(dur)
		if err != nil {
			return cfg, err
		}
	}

	fmt.Fprintln(out, "\nAuthorization:")
	fmt.Fprintln(out, "  This tool generates high-volume traffic. Only proceed if you own")
	fmt.Fprintln(out, "  the target or have explicit authorization from its owner.")
	auth, _ := ask("Do you assert authorization? (y/N): ")
	cfg.Authorized = strings.EqualFold(auth, "y") || strings.EqualFold(auth, "yes")
	if !cfg.Authorized {
		return cfg, errors.New("authorization not given — aborting")
	}

	allow, _ := ask("Allow public-IP targets? (y/N): ")
	cfg.AllowPublic = strings.EqualFold(allow, "y") || strings.EqualFold(allow, "yes")

	return cfg, nil
}
