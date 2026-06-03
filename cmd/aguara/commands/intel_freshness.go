package commands

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/garagon/aguara/internal/incident"
)

// intelStaleAfterDays is the age past which a user-fetched local /
// verified intel cache is treated as stale. The threshold is a CLI policy
// (the incident layer deliberately leaves IntelSummary.Stale unset so it
// does not own a freshness policy). Embedded intel is never stale: it
// ships with the binary, so its age is provenance, not an operational
// state the user neglected. Staleness is informational only -- it never
// affects exit codes, --fail-on, or the audit verdict.
const intelStaleAfterDays = 30

// applyIntelFreshness fills in AgeDays and Stale on an IntelSummary from
// its GeneratedAt relative to now. Only a non-embedded snapshot (a
// user-fetched local/verified/remote cache) can be stale. Pure given
// `now`, so it is unit-testable without a clock.
func applyIntelFreshness(s *incident.IntelSummary, now time.Time) {
	if s == nil || s.GeneratedAt.IsZero() {
		return
	}
	s.AgeDays = ageDaysSince(s.GeneratedAt, now)
	// Only a user-held local cache can be "stale": the stale note tells
	// the user to run `aguara update`, which only helps for local intel.
	// Embedded ships with the binary; remote-fresh was just fetched (if
	// the signed bundle itself is old, that is server-side, not a cache
	// the user neglected). So neither is ever flagged stale.
	s.Stale = (s.Snapshot == "local" || s.Snapshot == "local-verified") && s.AgeDays > intelStaleAfterDays
}

// ageDaysSince returns the whole-day age of t relative to now (0 for a
// zero or future timestamp).
func ageDaysSince(t, now time.Time) int {
	if t.IsZero() {
		return 0
	}
	age := now.Sub(t)
	if age < 0 {
		age = 0
	}
	return int(age / (24 * time.Hour))
}

// intelSourceLabel maps an IntelSummary.Snapshot value to friendly text.
func intelSourceLabel(snapshot string) string {
	switch snapshot {
	case "embedded":
		return "embedded"
	case "local":
		return "local"
	case "local-verified":
		return "local verified"
	case "remote-fresh":
		return "remote (fresh)"
	case "":
		return "embedded"
	default:
		return snapshot
	}
}

// humanizeAgeDays renders a whole-day age as a relative phrase.
func humanizeAgeDays(d int) string {
	switch {
	case d <= 0:
		return "today"
	case d == 1:
		return "1 day ago"
	default:
		return fmt.Sprintf("%d days ago", d)
	}
}

// intelFreshnessLine is the single-line provenance summary shown in
// check / audit terminal output, e.g.
//
//	Intel: embedded · generated 2026-06-01 (2 days ago) · sources: manual, osv
func intelFreshnessLine(s incident.IntelSummary) string {
	gen := "unknown"
	rel := ""
	if !s.GeneratedAt.IsZero() {
		gen = s.GeneratedAt.Format("2006-01-02")
		rel = " (" + humanizeAgeDays(s.AgeDays) + ")"
	}
	sources := "none"
	if len(s.Sources) > 0 {
		sources = strings.Join(s.Sources, ", ")
	}
	return fmt.Sprintf("Intel: %s · generated %s%s · sources: %s",
		intelSourceLabel(s.Snapshot), gen, rel, sources)
}

// intelStaleNote is the factual, non-alarmist note shown when a local
// cache is stale.
func intelStaleNote() string {
	return fmt.Sprintf("Note: local intel is older than %d days; run `aguara update` to refresh.", intelStaleAfterDays)
}

// printIntelFreshness writes the provenance line for a check/audit run.
// Outside CI it prints the line (and a stale note) to stdout. Under --ci
// stdout stays clean -- only a genuinely stale local cache earns a single
// note, and that goes to stderr so it never pollutes parsed output or
// affects the exit code.
func printIntelFreshness(s incident.IntelSummary, ci bool) {
	fprintIntelFreshness(os.Stdout, os.Stderr, s, ci)
}

// fprintIntelFreshness is the testable core of printIntelFreshness.
func fprintIntelFreshness(stdout, stderr io.Writer, s incident.IntelSummary, ci bool) {
	if ci {
		if s.Stale {
			fmt.Fprintln(stderr, intelStaleNote())
		}
		return
	}
	fmt.Fprintln(stdout, intelFreshnessLine(s))
	if s.Stale {
		fmt.Fprintln(stdout, intelStaleNote())
	}
}
