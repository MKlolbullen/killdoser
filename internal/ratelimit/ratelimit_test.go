package ratelimit

import (
	"context"
	"testing"
	"time"
)

func TestLimiterUnlimited(t *testing.T) {
	l := New(0)
	ctx := context.Background()
	start := time.Now()
	for i := 0; i < 1000; i++ {
		if err := l.Wait(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatalf("unlimited limiter was slow: %s", time.Since(start))
	}
}

func TestLimiterRespectsRate(t *testing.T) {
	// 100 rps with burst 100 -> 200 calls should take ~>=1s.
	l := New(100)
	ctx := context.Background()
	start := time.Now()
	for i := 0; i < 200; i++ {
		if err := l.Wait(ctx); err != nil {
			t.Fatal(err)
		}
	}
	elapsed := time.Since(start)
	if elapsed < 800*time.Millisecond {
		t.Fatalf("rate too loose: %s", elapsed)
	}
}

func TestLimiterCancellation(t *testing.T) {
	l := New(1) // tiny rate
	// Drain the single starting token so the next Wait must block.
	_ = l.Wait(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := l.Wait(ctx); err == nil {
		t.Fatal("expected context error")
	}
}
