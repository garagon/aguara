package output

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSpinnerStartStop(t *testing.T) {
	var buf bytes.Buffer
	sp := NewSpinner(&buf)
	sp.Start("Loading...")
	time.Sleep(200 * time.Millisecond)
	sp.Stop()

	out := buf.String()
	if !strings.Contains(out, "Loading...") {
		t.Errorf("expected spinner output to contain message, got %q", out)
	}
}

func TestSpinnerStopIdempotent(t *testing.T) {
	var buf bytes.Buffer
	sp := NewSpinner(&buf)
	sp.Start("test")
	time.Sleep(100 * time.Millisecond)

	// Calling Stop multiple times should not panic
	sp.Stop()
	sp.Stop()
	sp.Stop()
}

func TestSpinnerUpdate(t *testing.T) {
	var buf bytes.Buffer
	sp := NewSpinner(&buf)
	sp.Start("Phase 1")
	time.Sleep(150 * time.Millisecond)
	sp.Update("Phase 2")
	time.Sleep(150 * time.Millisecond)
	sp.Stop()

	out := buf.String()
	if !strings.Contains(out, "Phase 1") {
		t.Errorf("expected output to contain 'Phase 1', got %q", out)
	}
	if !strings.Contains(out, "Phase 2") {
		t.Errorf("expected output to contain 'Phase 2', got %q", out)
	}
}

func TestSpinnerConcurrentUpdate(t *testing.T) {
	var buf bytes.Buffer
	sp := NewSpinner(&buf)
	sp.Start("start")

	var wg sync.WaitGroup
	for i := range 10 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			sp.Update("msg")
		}(i)
	}
	wg.Wait()
	sp.Stop()
}

func TestSpinnerClearsLine(t *testing.T) {
	var buf bytes.Buffer
	sp := NewSpinner(&buf)
	sp.Start("working")
	time.Sleep(100 * time.Millisecond)
	sp.Stop()

	out := buf.String()
	// After Stop, the last write should be a \r followed by spaces (clearing)
	if !strings.HasSuffix(out, "\r") {
		t.Errorf("expected spinner to clear line with \\r at end")
	}
}
