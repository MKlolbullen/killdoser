package metrics

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRecordAndSnapshot(t *testing.T) {
	m := New(128)
	m.RecordAttempt()
	m.RecordSuccess(10*time.Millisecond, 100)
	m.RecordAttempt()
	m.RecordError("refused")

	s := m.Snapshot()
	if s.Attempts != 2 || s.Successes != 1 || s.Errors != 1 {
		t.Fatalf("counts wrong: %+v", s)
	}
	if s.ConnRefused != 1 {
		t.Fatalf("refused not classified: %+v", s)
	}
	if s.BytesSent != 100 {
		t.Fatalf("bytes: %d", s.BytesSent)
	}
	if s.LatencyP50 <= 0 {
		t.Fatalf("expected non-zero p50: %+v", s)
	}
	if s.SuccessPct <= 49 || s.SuccessPct >= 51 {
		t.Fatalf("success pct: %.2f", s.SuccessPct)
	}
}

func TestConcurrentRecords(t *testing.T) {
	m := New(1024)
	var wg sync.WaitGroup
	const workers = 16
	const per = 500
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < per; j++ {
				m.RecordAttempt()
				m.RecordSuccess(time.Duration(j)*time.Microsecond, 1)
			}
		}(i)
	}
	wg.Wait()
	s := m.Snapshot()
	if s.Attempts != workers*per || s.Successes != workers*per {
		t.Fatalf("lost updates: %+v", s)
	}
}

func TestReservoirBounded(t *testing.T) {
	m := New(64)
	for i := 0; i < 10_000; i++ {
		m.RecordAttempt()
		m.RecordSuccess(time.Duration(i)*time.Microsecond, 1)
	}
	m.mu.Lock()
	n := len(m.reservoir)
	m.mu.Unlock()
	if n != 64 {
		t.Fatalf("reservoir should be capped at 64, got %d", n)
	}
}

func TestSnapshotTextContainsKeyFields(t *testing.T) {
	m := New(64)
	m.RecordAttempt()
	m.RecordSuccess(time.Millisecond, 10)
	var buf bytes.Buffer
	m.Snapshot().WriteText(&buf)
	out := buf.String()
	for _, substr := range []string{"attempts=", "ok=", "rate=", "latency"} {
		if !strings.Contains(out, substr) {
			t.Errorf("summary missing %q:\n%s", substr, out)
		}
	}
}

func TestSnapshotJSON(t *testing.T) {
	m := New(64)
	m.RecordAttempt()
	m.RecordSuccess(time.Millisecond, 1)
	var buf bytes.Buffer
	if err := m.Snapshot().WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"attempts"`) {
		t.Fatalf("json missing fields: %s", buf.String())
	}
}
