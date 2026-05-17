package incident

import (
	"sync"
	"time"

	"github.com/garagon/aguara/internal/intel"
)

// defaultIntelMatcherOnce + defaultIntelMatcherCache lazily build
// the package-level matcher from EmbeddedSnapshots(). Lazy because
// KnownCompromisedSnapshot() walks the manual list every call;
// caching the matcher avoids re-walking on every check.
//
// The matcher is read-only after construction, so concurrent
// MatchPackage calls from the check pipeline are safe without
// further synchronisation.
var (
	defaultIntelMatcherOnce  sync.Once
	defaultIntelMatcherCache *intel.Matcher
)

// defaultIntelMatcher returns the singleton matcher built from
// the binary's embedded snapshots (manual + generated OSV stub).
// Both check entry points (Check / CheckNPM) consult it when no
// IntelOverride was passed.
//
// Exposing this as a package-private helper rather than a public
// variable means callers can not accidentally mutate the cached
// matcher, and tests in this package can still reach it for
// assertions through the same path.
func defaultIntelMatcher() *intel.Matcher {
	defaultIntelMatcherOnce.Do(func() {
		defaultIntelMatcherCache = intel.NewMatcher(EmbeddedSnapshots()...)
	})
	return defaultIntelMatcherCache
}

// matcherFor returns the matcher to use for a given CheckOptions.
// Nil Intel -> the cached default matcher; non-nil -> a fresh
// matcher built from the override's Snapshots. We deliberately
// do NOT cache override-built matchers because the override is a
// per-run construction (e.g. embedded + local cache) and the
// caching wins are negligible vs the simplicity cost.
func matcherFor(opts CheckOptions) *intel.Matcher {
	if opts.Intel == nil || len(opts.Intel.Snapshots) == 0 {
		return defaultIntelMatcher()
	}
	return intel.NewMatcher(opts.Intel.Snapshots...)
}

// MatcherForOverride exposes matcherFor's logic to callers that
// build a CheckResult outside the Check / CheckNPM path (e.g.
// the packagecheck Go runner in commands/check.go). Nil override
// -> the cached default matcher; non-nil -> a fresh matcher built
// from the override's Snapshots, same as the legacy paths.
func MatcherForOverride(override *IntelOverride) *intel.Matcher {
	return matcherFor(CheckOptions{Intel: override})
}

// IntelSummaryForOverride exposes intelSummaryFor's logic to
// callers building their own CheckResult. Returns the IntelSummary
// the override would have produced via CheckOptions; the
// Mode / SnapshotLabel / GeneratedAt / Sources / Stale fields stay
// consistent with what Check / CheckNPM would have emitted for the
// same override.
func IntelSummaryForOverride(override *IntelOverride) IntelSummary {
	return intelSummaryFor(CheckOptions{Intel: override})
}

// snapshotsFor returns the snapshot slice the check pipeline
// should iterate for non-matcher heuristics (e.g. the cache
// filename heuristic). Mirrors matcherFor so override callers
// have a consistent view of "what intel is in play this run".
func snapshotsFor(opts CheckOptions) []intel.Snapshot {
	if opts.Intel == nil || len(opts.Intel.Snapshots) == 0 {
		return EmbeddedSnapshots()
	}
	return opts.Intel.Snapshots
}

// intelSummaryFor returns the IntelSummary describing whichever
// snapshots the check actually consulted. Override Mode and
// SnapshotLabel win when set; everything else (GeneratedAt,
// Sources, Stale) is derived from the snapshots themselves so the
// summary cannot drift from the data.
func intelSummaryFor(opts CheckOptions) IntelSummary {
	mode := "offline"
	label := "embedded"
	if opts.Intel != nil {
		if opts.Intel.Mode != "" {
			mode = opts.Intel.Mode
		}
		if opts.Intel.SnapshotLabel != "" {
			label = opts.Intel.SnapshotLabel
		}
	}

	seen := make(map[string]struct{})
	var sources []string
	var generatedAt time.Time
	for _, snap := range snapshotsFor(opts) {
		if snap.GeneratedAt.After(generatedAt) {
			generatedAt = snap.GeneratedAt
		}
		for _, src := range snap.Sources {
			kind := string(src.Kind)
			if kind == "" {
				continue
			}
			if _, ok := seen[kind]; ok {
				continue
			}
			seen[kind] = struct{}{}
			sources = append(sources, kind)
		}
	}
	return IntelSummary{
		Mode:        mode,
		Snapshot:    label,
		GeneratedAt: generatedAt,
		Sources:     sources,
		Stale:       false,
	}
}

// KnownCompromisedSnapshot converts the hand-curated KnownCompromised
// list into an intel.Snapshot so it can be matched alongside future
// OSV-derived snapshots without callers having to know which source
// a record came from.
//
// The conversion is deterministic and pure: GeneratedAt is set to
// a fixed build-time stamp rather than time.Now() so the embedded
// snapshot is reproducible (matters for `go build -trimpath` and
// for the verify-release.sh path). Tests that need a live timestamp
// build snapshots via intel.Snapshot directly.
//
// Records carry KindMalicious or KindCompromised based on the entry
// Advisory shape: anything tagged as a historical or 2026 compromise
// of an otherwise-legitimate package is KindCompromised; standalone
// malicious typosquats are KindMalicious. The distinction is best-
// effort here -- the precise classification can be refined per entry
// as the manual list grows.
func KnownCompromisedSnapshot() intel.Snapshot {
	records := make([]intel.Record, 0, len(KnownCompromised))
	for _, cp := range KnownCompromised {
		eco := normalizeEcosystemForIntel(cp.Ecosystem)
		if eco == "" || cp.Name == "" {
			continue
		}
		records = append(records, intel.Record{
			ID:        cp.Advisory,
			Ecosystem: eco,
			Name:      cp.Name,
			// Every entry in KnownCompromised describes a
			// legitimate package whose specific versions were
			// hijacked (event-stream 3.3.6, litellm 1.82.7/.8,
			// node-ipc historical/2026 releases). The summary text
			// often mentions "malicious payload" or "malicious
			// dependency" -- that describes the payload, not the
			// package origin, so a keyword classifier would
			// mis-label these as KindMalicious. Pure malicious
			// typosquats do not belong on this manual list; if they
			// land later the entry should carry an explicit Kind
			// field rather than rely on summary heuristics.
			Kind:     intel.KindCompromised,
			Severity: "critical",
			Summary:  cp.Summary,
			Versions: append([]string(nil), cp.Versions...),
			IOCs:     convertIOCs(cp.IOCs),
		})
	}
	return intel.Snapshot{
		SchemaVersion: intel.CurrentSchemaVersion,
		GeneratedAt:   knownCompromisedGeneratedAt,
		Sources: []intel.SourceMeta{{
			Name: "aguara-manual-advisories",
			Kind: intel.SourceManual,
			URL:  "https://github.com/garagon/aguara",
		}},
		Records: records,
	}
}

// knownCompromisedGeneratedAt is the stamp used for the manual
// snapshot. Updated by hand when the manual list grows so consumers
// can detect a stale embedded snapshot. Reproducible across builds.
var knownCompromisedGeneratedAt = time.Date(2026, time.May, 15, 0, 0, 0, 0, time.UTC)

// normalizeEcosystemForIntel maps the legacy ecosystem strings used
// by CompromisedPackage entries to the canonical intel ecosystem
// identifiers. An empty input falls back to PyPI to match the
// historical IsCompromised behaviour (entries that pre-date the
// Ecosystem field are PyPI by convention).
func normalizeEcosystemForIntel(eco string) string {
	switch eco {
	case "", EcosystemPyPI:
		return intel.EcosystemPyPI
	case EcosystemNPM:
		return intel.EcosystemNPM
	default:
		return ""
	}
}

// EmbeddedSnapshots returns the per-source snapshots baked into
// the binary. The runtime matcher consumes them through
// intel.NewMatcher so the cross-snapshot merge / withdrawn-
// tombstone semantics apply: an OSV refresh that adds a fresh
// affected version surfaces it; an OSV record that retracts a
// manual entry tombstones the indexed match.
//
// Manual goes first so its metadata (Summary, Severity, IOCs)
// wins the first-occurrence merge for any advisory ID that
// appears in both sources. The OSV slice may be empty -- the
// generated file ships empty until the maintainer regenerates it
// from a fresh OSV dump.
func EmbeddedSnapshots() []intel.Snapshot {
	return []intel.Snapshot{
		KnownCompromisedSnapshot(),
		EmbeddedIntelSnapshot,
	}
}

// convertIOCs maps incident IOC entries to the intel-package IOC
// type. Returns nil rather than an empty slice when there are no
// IOCs so the JSON shape stays consistent across producers.
func convertIOCs(src []IOC) []intel.IOC {
	if len(src) == 0 {
		return nil
	}
	out := make([]intel.IOC, len(src))
	for i, ioc := range src {
		out[i] = intel.IOC{Type: ioc.Type, Value: ioc.Value}
	}
	return out
}
