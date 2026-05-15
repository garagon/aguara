package incident

import (
	"time"

	"github.com/garagon/aguara/internal/intel"
)

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

// embeddedIntelSummary returns the IntelSummary that describes the
// snapshot baked into the binary. Used by Check and CheckNPM so
// every CheckResult carries provenance even when no runtime intel
// store has been wired in yet.
//
// Mode stays "offline" because PR 2 has no network path; PR 4 will
// flip Mode to "online" when --fresh produced the snapshot used.
// Snapshot stays "embedded" because the local on-disk cache is not
// consulted here yet.
func embeddedIntelSummary() IntelSummary {
	snap := KnownCompromisedSnapshot()
	sources := make([]string, 0, len(snap.Sources))
	for _, src := range snap.Sources {
		sources = append(sources, string(src.Kind))
	}
	return IntelSummary{
		Mode:        "offline",
		Snapshot:    "embedded",
		GeneratedAt: snap.GeneratedAt,
		Sources:     sources,
		Stale:       false,
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
