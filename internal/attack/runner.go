package attack

import (
	"context"
	"sync"

	"github.com/MKlolbullen/killdoser/internal/metrics"
	"github.com/MKlolbullen/killdoser/internal/ratelimit"
	"github.com/MKlolbullen/killdoser/internal/target"
)

// Job describes a single unit of work for a worker.
type Job struct {
	Endpoint target.Endpoint
}

// RunConfig parameterises a test run.
type RunConfig struct {
	Workers   int
	Endpoints []target.Endpoint
	Attacker  Attacker
	Limiter   *ratelimit.Limiter
	Metrics   *metrics.Metrics
	// TotalJobs caps the number of sends. 0 means "run until ctx is done".
	TotalJobs uint64
}

// Run executes the configured attack until ctx is cancelled or TotalJobs
// sends have been issued. It returns when all workers have drained.
func Run(ctx context.Context, cfg RunConfig) {
	if cfg.Workers < 1 {
		cfg.Workers = 1
	}
	jobs := make(chan Job, cfg.Workers*2)

	var wg sync.WaitGroup
	for i := 0; i < cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					return
				}
				cfg.Attacker.Send(ctx, j.Endpoint, cfg.Metrics)
			}
		}()
	}

	// Dispatcher: round-robin endpoints, rate-limited.
	go func() {
		defer close(jobs)
		var n uint64
		for i := 0; ; i++ {
			if ctx.Err() != nil {
				return
			}
			if cfg.TotalJobs > 0 && n >= cfg.TotalJobs {
				return
			}
			if cfg.Limiter != nil {
				if err := cfg.Limiter.Wait(ctx); err != nil {
					return
				}
			}
			ep := cfg.Endpoints[i%len(cfg.Endpoints)]
			select {
			case <-ctx.Done():
				return
			case jobs <- Job{Endpoint: ep}:
				n++
			}
		}
	}()

	wg.Wait()
}
