package commands

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/garagon/aguara/internal/incident"
)

func TestApplyIntelFreshness(t *testing.T) {
	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	day := func(n int) time.Time { return now.AddDate(0, 0, -n) }

	cases := []struct {
		name        string
		snapshot    string
		generatedAt time.Time
		wantAge     int
		wantStale   bool
	}{
		{"embedded recent", "embedded", day(2), 2, false},
		// Embedded is never stale, no matter how old (it ships with the binary).
		{"embedded ancient never stale", "embedded", day(400), 400, false},
		{"local-verified fresh", "local-verified", day(5), 5, false},
		{"local-verified at threshold not stale", "local-verified", day(30), 30, false},
		{"local-verified over threshold stale", "local-verified", day(31), 31, true},
		{"local old stale", "local", day(100), 100, true},
		{"remote-fresh not stale", "remote-fresh", day(0), 0, false},
		// A just-fetched bundle is never "stale" even if its own
		// generated_at is old; `aguara update` would not change anything.
		{"remote-fresh old never stale", "remote-fresh", day(120), 120, false},
		{"plain local old stale", "local", day(45), 45, true},
		{"zero time is a no-op", "local-verified", time.Time{}, 0, false},
		{"future time clamps to zero age", "local-verified", now.AddDate(0, 0, 5), 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &incident.IntelSummary{Snapshot: c.snapshot, GeneratedAt: c.generatedAt}
			applyIntelFreshness(s, now)
			if s.AgeDays != c.wantAge {
				t.Errorf("AgeDays = %d, want %d", s.AgeDays, c.wantAge)
			}
			if s.Stale != c.wantStale {
				t.Errorf("Stale = %v, want %v", s.Stale, c.wantStale)
			}
		})
	}
}

func TestApplyIntelFreshnessNilSafe(t *testing.T) {
	applyIntelFreshness(nil, time.Now()) // must not panic
}

func TestHumanizeAgeDays(t *testing.T) {
	cases := map[int]string{0: "today", 1: "1 day ago", 2: "2 days ago", 33: "33 days ago"}
	for d, want := range cases {
		if got := humanizeAgeDays(d); got != want {
			t.Errorf("humanizeAgeDays(%d) = %q, want %q", d, got, want)
		}
	}
}

func TestIntelFreshnessLine(t *testing.T) {
	s := incident.IntelSummary{
		Snapshot:    "embedded",
		GeneratedAt: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		AgeDays:     2,
		Sources:     []string{"manual", "osv"},
	}
	got := intelFreshnessLine(s)
	want := "Intel: embedded · generated 2026-06-01 (2 days ago) · sources: manual, osv"
	if got != want {
		t.Errorf("line = %q, want %q", got, want)
	}
}

func TestFprintIntelFreshness(t *testing.T) {
	fresh := incident.IntelSummary{
		Snapshot: "local-verified", GeneratedAt: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		AgeDays: 2, Sources: []string{"manual"}, Stale: false,
	}
	stale := incident.IntelSummary{
		Snapshot: "local-verified", GeneratedAt: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
		AgeDays: 33, Sources: []string{"manual"}, Stale: true,
	}

	t.Run("non-ci prints the line on stdout", func(t *testing.T) {
		var out, errb bytes.Buffer
		fprintIntelFreshness(&out, &errb, fresh, false)
		if !strings.Contains(out.String(), "Intel: local verified") {
			t.Errorf("stdout missing intel line: %q", out.String())
		}
		if errb.Len() != 0 {
			t.Errorf("stderr should be empty, got %q", errb.String())
		}
	})

	t.Run("non-ci stale adds note on stdout", func(t *testing.T) {
		var out, errb bytes.Buffer
		fprintIntelFreshness(&out, &errb, stale, false)
		if !strings.Contains(out.String(), "older than 30 days") {
			t.Errorf("stdout missing stale note: %q", out.String())
		}
	})

	t.Run("ci suppresses the line on stdout", func(t *testing.T) {
		var out, errb bytes.Buffer
		fprintIntelFreshness(&out, &errb, fresh, true)
		if out.Len() != 0 {
			t.Errorf("ci stdout must be empty, got %q", out.String())
		}
		if errb.Len() != 0 {
			t.Errorf("ci stderr should be empty for fresh intel, got %q", errb.String())
		}
	})

	t.Run("ci stale notes on stderr only", func(t *testing.T) {
		var out, errb bytes.Buffer
		fprintIntelFreshness(&out, &errb, stale, true)
		if out.Len() != 0 {
			t.Errorf("ci stdout must stay clean, got %q", out.String())
		}
		if !strings.Contains(errb.String(), "older than 30 days") {
			t.Errorf("ci stderr missing stale note: %q", errb.String())
		}
	})
}
