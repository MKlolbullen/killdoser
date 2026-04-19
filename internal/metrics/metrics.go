// Package metrics collects counters and latency samples from in-flight tests.
//
// The hot path is lock-free: Record* methods use atomic adds. Latency samples
// are stored in a bounded reservoir (Vitter's Algorithm R) so long-running
// tests don't grow unbounded, yet percentiles remain representative.
package metrics

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Metrics aggregates counters for a single test run.
type Metrics struct {
	startedAt time.Time

	attempts  atomic.Uint64
	successes atomic.Uint64
	errors    atomic.Uint64
	bytesSent atomic.Uint64
	connRefused atomic.Uint64
	connTimeout atomic.Uint64

	mu        sync.Mutex
	reservoir []time.Duration
	seen      uint64
	rng       *rand.Rand
	errKinds  map[string]uint64
}

// New constructs a Metrics instance with the given reservoir capacity.
// Capacity is the maximum number of latency samples retained.
func New(reservoirCap int) *Metrics {
	if reservoirCap < 64 {
		reservoirCap = 64
	}
	return &Metrics{
		startedAt: time.Now(),
		reservoir: make([]time.Duration, 0, reservoirCap),
		rng:       rand.New(rand.NewSource(time.Now().UnixNano())),
		errKinds:  make(map[string]uint64),
	}
}

// RecordAttempt increments the attempt counter (called once per send).
func (m *Metrics) RecordAttempt() { m.attempts.Add(1) }

// RecordSuccess records a successful send, its latency, and bytes written.
func (m *Metrics) RecordSuccess(latency time.Duration, bytes int) {
	m.successes.Add(1)
	if bytes > 0 {
		m.bytesSent.Add(uint64(bytes))
	}
	m.sampleLatency(latency)
}

// RecordError records a failed attempt and classifies the error.
func (m *Metrics) RecordError(kind string) {
	m.errors.Add(1)
	switch kind {
	case "refused":
		m.connRefused.Add(1)
	case "timeout":
		m.connTimeout.Add(1)
	}
	if kind == "" {
		return
	}
	m.mu.Lock()
	m.errKinds[kind]++
	m.mu.Unlock()
}

func (m *Metrics) sampleLatency(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seen++
	if len(m.reservoir) < cap(m.reservoir) {
		m.reservoir = append(m.reservoir, d)
		return
	}
	// Vitter Algorithm R.
	idx := m.rng.Int63n(int64(m.seen))
	if int(idx) < cap(m.reservoir) {
		m.reservoir[idx] = d
	}
}

// Snapshot captures a consistent view of metrics at a moment in time.
type Snapshot struct {
	Elapsed     time.Duration    `json:"elapsed"`
	Attempts    uint64           `json:"attempts"`
	Successes   uint64           `json:"successes"`
	Errors      uint64           `json:"errors"`
	BytesSent   uint64           `json:"bytes_sent"`
	ConnRefused uint64           `json:"conn_refused"`
	ConnTimeout uint64           `json:"conn_timeout"`
	RateRPS     float64          `json:"rate_rps"`
	SuccessPct  float64          `json:"success_pct"`
	LatencyP50  time.Duration    `json:"latency_p50"`
	LatencyP95  time.Duration    `json:"latency_p95"`
	LatencyP99  time.Duration    `json:"latency_p99"`
	LatencyMax  time.Duration    `json:"latency_max"`
	ErrorKinds  map[string]uint64 `json:"error_kinds,omitempty"`
}

// Snapshot returns the current counters and latency percentiles.
func (m *Metrics) Snapshot() Snapshot {
	elapsed := time.Since(m.startedAt)
	attempts := m.attempts.Load()
	successes := m.successes.Load()
	errors := m.errors.Load()

	var rate float64
	if elapsed > 0 {
		rate = float64(attempts) / elapsed.Seconds()
	}
	var pct float64
	if attempts > 0 {
		pct = float64(successes) * 100 / float64(attempts)
	}

	m.mu.Lock()
	samples := append([]time.Duration(nil), m.reservoir...)
	errKinds := make(map[string]uint64, len(m.errKinds))
	for k, v := range m.errKinds {
		errKinds[k] = v
	}
	m.mu.Unlock()

	p50, p95, p99, max := percentiles(samples)

	return Snapshot{
		Elapsed:     elapsed,
		Attempts:    attempts,
		Successes:   successes,
		Errors:      errors,
		BytesSent:   m.bytesSent.Load(),
		ConnRefused: m.connRefused.Load(),
		ConnTimeout: m.connTimeout.Load(),
		RateRPS:     rate,
		SuccessPct:  pct,
		LatencyP50:  p50,
		LatencyP95:  p95,
		LatencyP99:  p99,
		LatencyMax:  max,
		ErrorKinds:  errKinds,
	}
}

func percentiles(samples []time.Duration) (p50, p95, p99, max time.Duration) {
	if len(samples) == 0 {
		return 0, 0, 0, 0
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	pick := func(p float64) time.Duration {
		if len(samples) == 0 {
			return 0
		}
		idx := int(p * float64(len(samples)-1))
		if idx < 0 {
			idx = 0
		}
		if idx >= len(samples) {
			idx = len(samples) - 1
		}
		return samples[idx]
	}
	return pick(0.50), pick(0.95), pick(0.99), samples[len(samples)-1]
}

// WriteText renders a human-readable summary to w.
func (s Snapshot) WriteText(w io.Writer) {
	fmt.Fprintf(w, "elapsed=%s attempts=%d ok=%d err=%d (%.1f%%) rate=%.0f/s bytes=%d\n",
		s.Elapsed.Round(time.Millisecond), s.Attempts, s.Successes, s.Errors,
		s.SuccessPct, s.RateRPS, s.BytesSent)
	fmt.Fprintf(w, "latency p50=%s p95=%s p99=%s max=%s\n",
		s.LatencyP50.Round(time.Microsecond),
		s.LatencyP95.Round(time.Microsecond),
		s.LatencyP99.Round(time.Microsecond),
		s.LatencyMax.Round(time.Microsecond))
	if s.ConnRefused > 0 || s.ConnTimeout > 0 {
		fmt.Fprintf(w, "refused=%d timeout=%d\n", s.ConnRefused, s.ConnTimeout)
	}
	if len(s.ErrorKinds) > 0 {
		keys := make([]string, 0, len(s.ErrorKinds))
		for k := range s.ErrorKinds {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Fprintf(w, "errors:")
		for _, k := range keys {
			fmt.Fprintf(w, " %s=%d", k, s.ErrorKinds[k])
		}
		fmt.Fprintln(w)
	}
}

// WriteJSON renders the snapshot as JSON to w.
func (s Snapshot) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}
