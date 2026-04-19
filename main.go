// KillDoSer: a firewall/service stress-testing harness.
//
// This binary is a thin orchestrator: it wires the internal packages
// (config, safety, target, attack, metrics, ratelimit) together, prints a
// progress line periodically, and ensures graceful shutdown on SIGINT/TERM.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/MKlolbullen/killdoser/internal/attack"
	"github.com/MKlolbullen/killdoser/internal/config"
	"github.com/MKlolbullen/killdoser/internal/metrics"
	"github.com/MKlolbullen/killdoser/internal/ratelimit"
	"github.com/MKlolbullen/killdoser/internal/safety"
	"github.com/MKlolbullen/killdoser/internal/target"
)

func main() {
	code, err := run(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
	}
	os.Exit(code)
}

func run(args []string) (int, error) {
	cfg, err := config.ParseFlags(args)
	if errors.Is(err, flag.ErrHelp) {
		config.Usage(os.Stdout)
		return 0, nil
	}
	if err != nil {
		config.Usage(os.Stderr)
		return 2, err
	}

	fmt.Fprint(os.Stdout, safety.AuthorizationNotice)

	if cfg.Interactive {
		cfg, err = config.Wizard(os.Stdin, os.Stdout)
		if err != nil {
			return 2, err
		}
	}
	if err := cfg.ApplyEncoding(); err != nil {
		return 2, err
	}
	if err := cfg.Validate(); err != nil {
		return 2, err
	}

	policy := safety.DefaultPolicy()
	policy.Authorized = cfg.Authorized
	policy.AllowPublic = cfg.AllowPublic
	if err := policy.CheckAuthorized(); err != nil {
		return 2, err
	}
	cfg.Workers = policy.NormaliseWorkers(cfg.Workers)
	cfg.RatePPS = policy.NormaliseRate(cfg.RatePPS)

	endpoints, err := target.Parse(target.Spec{Raw: cfg.Target, DefaultPort: cfg.Port})
	if err != nil {
		return 2, err
	}
	for _, ep := range endpoints {
		if err := policy.CheckTarget(ep.IP); err != nil {
			return 2, err
		}
	}

	attacker, err := buildAttacker(cfg)
	if err != nil {
		return 2, err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if cfg.Duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.Duration)
		defer cancel()
	}

	m := metrics.New(4096)

	fmt.Fprintf(os.Stdout, "starting %s against %d endpoint(s), workers=%d rate=%d/s duration=%s count=%d\n",
		attacker.Name(), len(endpoints), cfg.Workers, cfg.RatePPS, cfg.Duration, cfg.Count)

	if !cfg.Quiet {
		go progressLoop(ctx, m)
	}

	limiter := ratelimit.New(cfg.RatePPS)
	attack.Run(ctx, attack.RunConfig{
		Workers:   cfg.Workers,
		Endpoints: endpoints,
		Attacker:  attacker,
		Limiter:   limiter,
		Metrics:   m,
		TotalJobs: cfg.Count,
	})

	snap := m.Snapshot()
	fmt.Fprintln(os.Stdout, "\n=== KillDoSer summary ===")
	if cfg.JSONOutput {
		if err := snap.WriteJSON(os.Stdout); err != nil {
			return 1, err
		}
	} else {
		snap.WriteText(os.Stdout)
	}
	return 0, nil
}

func buildAttacker(cfg config.Config) (attack.Attacker, error) {
	payload := []byte(cfg.Payload)
	switch cfg.Mode {
	case config.ModeTCP:
		return &attack.TCPConnect{
			Payload:        payload,
			Timeout:        cfg.Timeout,
			ReadAfterWrite: true,
		}, nil
	case config.ModeUDP:
		return &attack.UDPFlood{Payload: payload, Timeout: cfg.Timeout}, nil
	case config.ModeHTTP:
		return &attack.HTTPFlood{
			Method:   cfg.HTTPMethod,
			Path:     cfg.HTTPPath,
			Scheme:   cfg.HTTPScheme,
			HostHdr:  cfg.HTTPHostHeader,
			Body:     payload,
			UseHTTP2: cfg.HTTPUseH2,
			Timeout:  cfg.Timeout,
			Insecure: cfg.HTTPInsecure,
		}, nil
	case config.ModeSlowloris:
		return &attack.Slowloris{
			Path:           cfg.HTTPPath,
			HostHdr:        cfg.HTTPHostHeader,
			HeaderCount:    cfg.SlowHeaders,
			HeaderInterval: cfg.SlowInterval,
			DialTimeout:    cfg.Timeout,
			TLS:            cfg.HTTPScheme == "https",
			Insecure:       cfg.HTTPInsecure,
		}, nil
	}
	return nil, fmt.Errorf("unknown mode %q", cfg.Mode)
}

func progressLoop(ctx context.Context, m *metrics.Metrics) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s := m.Snapshot()
			fmt.Fprintf(os.Stderr,
				"[%s] attempts=%d ok=%d err=%d rate=%.0f/s p95=%s\n",
				s.Elapsed.Round(time.Second), s.Attempts, s.Successes, s.Errors,
				s.RateRPS, s.LatencyP95.Round(time.Millisecond),
			)
		}
	}
}
