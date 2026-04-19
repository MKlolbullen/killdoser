// Package ratelimit provides a simple token-bucket limiter used to cap the
// total send rate across all workers in a test run.
package ratelimit

import (
	"context"
	"sync"
	"time"
)

// Limiter allows up to `ratePerSec` Wait calls to proceed per second, with
// burst capacity equal to `ratePerSec`. A rate of 0 means unlimited.
type Limiter struct {
	mu         sync.Mutex
	rate       int
	capacity   float64
	tokens     float64
	lastRefill time.Time
}

// New creates a Limiter. Rate 0 means unlimited (Wait is a no-op).
func New(ratePerSec int) *Limiter {
	burst := float64(ratePerSec)
	if burst < 1 {
		burst = 1
	}
	return &Limiter{
		rate:       ratePerSec,
		capacity:   burst,
		tokens:     burst,
		lastRefill: time.Now(),
	}
}

// Wait blocks until a token is available or ctx is cancelled.
func (l *Limiter) Wait(ctx context.Context) error {
	if l.rate <= 0 {
		return ctx.Err()
	}
	for {
		l.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(l.lastRefill).Seconds()
		l.tokens += elapsed * float64(l.rate)
		if l.tokens > l.capacity {
			l.tokens = l.capacity
		}
		l.lastRefill = now
		if l.tokens >= 1 {
			l.tokens--
			l.mu.Unlock()
			return nil
		}
		wait := time.Duration((1 - l.tokens) / float64(l.rate) * float64(time.Second))
		l.mu.Unlock()
		if wait < time.Millisecond {
			wait = time.Millisecond
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}
