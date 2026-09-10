// Package osvimport converts OSV.dev JSON dumps into intel.Snapshot
// values that the runtime matcher can consume.
//
// Scope is deliberately narrow: only high-confidence malicious or
// compromised package records survive the filter. Exact versions, all-version
// advisories and supported npm ranges are retained only with admission evidence.
//
// This package is pure: it does no I/O of its own. ImportFromZip
// (in zip.go) is a small helper that reads OSV's all.zip dumps and
// feeds Import; SortRecords (in sort.go) puts records in the canonical
// order the generator emits. The resulting snapshot is serialised to
// the embedded binary blob by intel.EncodeSnapshotGZIP.
package osvimport

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/garagon/aguara/internal/intel"
)

// Options control which records survive the filter. All fields are
// optional; the zero value selects the production-default filter
// (MAL- IDs, structured OpenSSF origins, and exact-version admissions from
// reviewed GitHub CWE-506 classifications or the reviewed compatibility list).
type Options struct {
	// Ecosystems is the set of OSV ecosystem strings to keep.
	// Empty means "no filter" -- import everything OSV emits, which
	// is rarely what callers want. Production callers should pass
	// {"npm", "PyPI"}.
	Ecosystems []string
	// MinSeverity, when set, drops any record whose severity is
	// strictly below this value. Empty means "no filter". Reserved
	// for a future PR; currently unused because OSV malicious
	// records do not carry a severity score.
	MinSeverity string
	// GeneratedAt overrides the timestamp the produced snapshot
	// carries. Used by tests to keep output reproducible; production
	// callers leave this zero so the importer stamps time.Now().UTC().
	GeneratedAt time.Time
	// SourceName overrides the SourceMeta.Name on the produced
	// snapshot. Defaults to "osv.dev".
	SourceName string
}

// osvRecord mirrors the subset of the OSV schema we consume. The
// real schema is much larger; we only decode fields the filter or
// the resulting intel.Record needs so unknown future fields are
// silently ignored.
//
// Field shapes:
//   - Aliases is a list of equivalent advisory IDs (e.g. an MAL-
//     record aliased to a GHSA-).
//   - Affected is keyed by package; each entry holds an ecosystem,
//     a name, and an optional Versions list of exact strings.
//   - DatabaseSpecific carries source-specific metadata; OpenSSF
//     Malicious Packages records populate it with origin info.
//   - References lists supporting URLs; these are not admission evidence.
type osvRecord struct {
	ID               string          `json:"id"`
	Aliases          []string        `json:"aliases,omitempty"`
	Modified         time.Time       `json:"modified,omitempty"`
	Published        time.Time       `json:"published,omitempty"`
	Withdrawn        string          `json:"withdrawn,omitempty"`
	Summary          string          `json:"summary,omitempty"`
	Details          string          `json:"details,omitempty"`
	Affected         []osvAffected   `json:"affected,omitempty"`
	References       []osvReference  `json:"references,omitempty"`
	DatabaseSpecific json.RawMessage `json:"database_specific,omitempty"`
}

type osvAffected struct {
	Package  osvPackage `json:"package"`
	Versions []string   `json:"versions,omitempty"`
	Ranges   []osvRange `json:"ranges,omitempty"`
}

type osvRange struct {
	Type   string              `json:"type"`
	Events []map[string]string `json:"events"`
}

// rangesAllVersionsShape reports whether every range consists solely
// of introduced 0/absent events: the "every version is malicious"
// shape. Any other event key (fixed, last_affected, limit, future
// additions) bounds the range and disqualifies the record from the
// compact all-versions encoding.
func rangesAllVersionsShape(in []osvRange) bool {
	if len(in) == 0 {
		return false
	}
	for _, r := range in {
		introduced := false
		for _, ev := range r.Events {
			for k, v := range ev {
				if k != "introduced" {
					return false
				}
				if v != "" && v != "0" {
					return false
				}
				introduced = true
			}
		}
		// A range with no events (or only empty maps) asserts
		// nothing; flagging every version from it would invent
		// coverage OSV never stated.
		if !introduced {
			return false
		}
	}
	return true
}

// convertRanges maps OSV ranges onto intel.VersionRange. Each OSV
// range may carry several introduced/fixed event pairs; OSV events
// come ordered, so pairs are formed sequentially: an introduced event
// opens a range, a fixed/last_affected event closes it.
func convertRanges(in []osvRange) []intel.VersionRange {
	var out []intel.VersionRange
	for _, r := range in {
		cur := intel.VersionRange{Type: r.Type}
		open := false
		for _, ev := range r.Events {
			if v, ok := ev["introduced"]; ok {
				if open {
					out = append(out, cur)
					cur = intel.VersionRange{Type: r.Type}
				}
				cur.Introduced = v
				open = true
			}
			if v, ok := ev["fixed"]; ok {
				cur.Fixed = v
			}
			if v, ok := ev["last_affected"]; ok {
				cur.LastAffected = v
			}
			if v, ok := ev["limit"]; ok && v != "" {
				// OSV `limit` caps the range's domain (exclusive):
				// versions below it follow the events as stated,
				// versions at/above it are outside the range. Closing
				// the open segment at the limit is therefore
				// conservative-correct (never flags above the limit),
				// and events past the limit are outside the domain,
				// so processing stops for this range.
				if open && cur.Fixed == "" && cur.LastAffected == "" {
					cur.Fixed = v
				}
				break
			}
		}
		if open {
			out = append(out, cur)
		}
	}
	return out
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvReference struct {
	Type string `json:"type,omitempty"`
	URL  string `json:"url,omitempty"`
}

// Import returns the intel.Snapshot for the given OSV record set.
// Caller is responsible for feeding the full set of records they
// want considered; Import does not perform any I/O. Records that
// fail the filter are silently dropped (they are not surfaced as
// errors because OSV dumps contain large volumes of non-malicious
// records that intentionally do not qualify).
//
// raw is a slice of json.RawMessage so callers can stream records
// out of a zip / HTTP body without materialising them as Go structs
// twice. The function parses each record once.
func Import(raw [][]byte, opts Options) (intel.Snapshot, error) {
	ecoFilter, err := buildEcosystemFilter(opts.Ecosystems)
	if err != nil {
		return intel.Snapshot{}, err
	}

	snap := intel.Snapshot{
		SchemaVersion:   intel.CurrentSchemaVersion,
		AdmissionPolicy: intel.CurrentOSVAdmissionPolicy,
		GeneratedAt:     opts.GeneratedAt,
	}
	if snap.GeneratedAt.IsZero() {
		snap.GeneratedAt = time.Now().UTC()
	}
	sourceName := opts.SourceName
	if sourceName == "" {
		sourceName = "osv.dev"
	}
	snap.Sources = []intel.SourceMeta{{
		Name:        sourceName,
		Kind:        intel.SourceOSV,
		URL:         "https://osv.dev",
		RetrievedAt: snap.GeneratedAt,
		License:     "CC-BY-4.0",
	}}

	for _, b := range raw {
		rec, entries, ok := convertOSVRecord(b, ecoFilter)
		if !ok {
			continue
		}
		snap.Records = append(snap.Records, rec...)
		snap.AllVersions = append(snap.AllVersions, entries...)
	}

	// Stable order for reproducible builds: ecosystem, name, ID.
	// Without this the embedded snapshot would re-shuffle on every
	// regeneration even when the upstream OSV slice is identical.
	snap.AllVersions = SortAndDedupeAllVersions(snap.AllVersions)

	sort.SliceStable(snap.Records, func(i, j int) bool {
		a, b := snap.Records[i], snap.Records[j]
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.ID < b.ID
	})

	return snap, nil
}

// convertOSVRecord decides whether a single OSV record qualifies
// and produces zero or more intel.Records. Most OSV records affect
// a single (ecosystem, name) tuple, but the schema allows multiple;
// each surviving affected entry becomes one intel.Record so the
// runtime matcher can index by (ecosystem, name) without further
// fanning-out.
//
// Returns (records, true) on a kept advisory; (nil, false) on
// anything dropped by the filter.
func convertOSVRecord(raw []byte, ecoFilter map[string]struct{}) ([]intel.Record, []intel.AllVersionsEntry, bool) {
	var osv osvRecord
	if err := json.Unmarshal(raw, &osv); err != nil {
		// Malformed record: drop rather than abort the whole
		// import. A single bad row in a 100k-record OSV dump
		// must not deny-of-service the rest of the snapshot.
		return nil, nil, false
	}
	if osv.ID == "" || len(osv.Affected) == 0 {
		return nil, nil, false
	}

	// A withdrawn-in-OSV record passes through as a withdrawn
	// intel.Record so the matcher's tombstone path retracts any
	// earlier live copy from another source. The tombstone keys
	// off (ecosystem, name, ID) only, so a withdrawn record does
	// not need to satisfy the empty-versions or admission
	// gates that live records do.
	withdrawn := osv.Withdrawn != ""

	signal := hasHighConfidenceSignal(osv)

	var out []intel.Record
	var entries []intel.AllVersionsEntry
	for _, aff := range osv.Affected {
		eco := canonicaliseEcosystem(aff.Package.Ecosystem)
		if eco == "" {
			continue
		}
		if ecoFilter != nil {
			if _, ok := ecoFilter[eco]; !ok {
				continue
			}
		}

		// Withdrawn records bypass both the empty-versions skip
		// and the admission gate. They exist purely so the
		// matcher can tombstone an earlier live copy with the
		// same advisory ID; if we filter them out here, the live
		// copy keeps matching forever after the retraction.
		if !withdrawn {
			if len(aff.Versions) == 0 {
				// No exact versions. If the record is malicious and
				// every range is the all-versions shape, it becomes a
				// compact AllVersionsEntry: an exact (ecosystem, name)
				// lookup is its whole evaluation, no version grammar
				// involved. The range channels require the firm
				// signal (MAL- / OpenSSF origins), NOT the keyword
				// gate: a keyword false positive on an exact-version
				// record flags a handful of versions, but the same
				// false positive on a range flags every version below
				// the bound (measured leak: axios, @angular/core,
				// playwright CVEs arriving as "malicious"). The
				// Exact-version admissions are handled separately below.
				if signal && rangesAllVersionsShape(aff.Ranges) {
					entries = append(entries, intel.AllVersionsEntry{
						ID:        osv.ID,
						Ecosystem: eco,
						Name:      aff.Package.Name,
					})
					continue
				}
				// Bounded malicious ranges (real version bounds) ship
				// as full Records WITH Ranges - npm only (C3-B): the
				// matcher's range evaluation is gated to npm's semver
				// grammar (ecosystemSupportsRanges), so importing
				// bounded ranges for any other ecosystem would embed
				// dead data. Signal-only, same reasoning as the
				// all-versions channel above.
				if signal && eco == "npm" {
					// A range whose events never open (no introduced)
					// converts to nothing, and a range type the
					// matcher cannot evaluate (e.g. GIT) would import
					// as dead data; both are dropped.
					if rngs := evaluableRanges(convertRanges(aff.Ranges)); len(rngs) > 0 {
						out = append(out, intel.Record{
							ID:         osv.ID,
							Aliases:    append([]string(nil), osv.Aliases...),
							Ecosystem:  eco,
							Name:       aff.Package.Name,
							Kind:       intel.KindMalicious,
							Summary:    pickSummary(osv),
							Ranges:     rngs,
							References: extractReferenceURLs(osv.References),
						})
					}
				}
				continue
			}
			// Exact versions define affected scope, not malicious intent.
			aff.Versions = admittedExactVersions(osv, eco, aff, signal)
			if len(aff.Versions) == 0 {
				continue
			}
		}

		out = append(out, intel.Record{
			ID:         osv.ID,
			Aliases:    append([]string(nil), osv.Aliases...),
			Ecosystem:  eco,
			Name:       aff.Package.Name,
			Kind:       intel.KindMalicious,
			Summary:    pickSummary(osv),
			Versions:   append([]string(nil), aff.Versions...),
			References: extractReferenceURLs(osv.References),
			Withdrawn:  withdrawn,
		})
	}
	if len(out) == 0 && len(entries) == 0 {
		return nil, nil, false
	}
	return out, entries, true
}

// RecordStatus is the per-record verdict the filter funnel produces.
// Used by ClassifyForEcosystem so diagnostic / measurement tooling
// can count how each ecosystem's OSV bucket would fare against the
// production importer without re-implementing the filter.
type RecordStatus int

const (
	// StatusEcosystemMiss: the record is malformed, empty, or
	// does not have an affected[] entry for the target ecosystem.
	StatusEcosystemMiss RecordStatus = iota
	// StatusWithdrawn: the record is retracted in OSV. The
	// production importer emits a tombstone in this case; the
	// classifier returns an empty Record so callers do not have
	// to discriminate.
	StatusWithdrawn
	// StatusRangesOnly: the affected entry carries only version
	// ranges, no exact versions. The matcher consumes exact
	// versions only, so the record is dropped from the snapshot.
	StatusRangesOnly
	// StatusNeither: the record has exact versions but lacks source
	// evidence or explicitly reviewed tuples. Generic CVEs land
	// here and do not belong in a malicious-package snapshot.
	StatusNeither
	// StatusKept: the record survives the filter and becomes an
	// intel.Record in the snapshot.
	StatusKept
	// StatusRangesOnlyMalicious: only version ranges with REAL
	// bounds (fixed / last_affected / non-zero introduced), no exact
	// versions, and the record passes the malicious gate. Dropped
	// from the snapshot today; this is the bounded-range residual
	// (C3-B). Appended after StatusKept so existing status values
	// are stable.
	StatusRangesOnlyMalicious
	// StatusAllVersionsKept: no exact versions, malicious, and every
	// range is the all-versions shape (introduced 0/absent, nothing
	// else). The importer KEEPS these as compact
	// Snapshot.AllVersions entries (C3-A), so measurement tooling
	// must count them as kept intel, not dropped.
	StatusAllVersionsKept
)

// ClassifyForEcosystem walks a raw OSV record and reports how a
// single (target-ecosystem) affected entry would fare against the
// importer's filter. It is the counters-friendly variant of
// Import: production callers should use Import / ImportFromZip,
// but measurement and diagnostic tooling (tools/measure-intel)
// needs the per-status breakdown that Import collapses away.
//
// The function is pure and safe for concurrent use. Returns
// (intel.Record{}, StatusEcosystemMiss) when the target ecosystem
// is unknown to the registry or absent from the record.
func ClassifyForEcosystem(raw []byte, targetEcosystem string) (intel.Record, RecordStatus) {
	canon := canonicaliseEcosystem(targetEcosystem)
	if canon == "" {
		return intel.Record{}, StatusEcosystemMiss
	}
	var osv osvRecord
	if err := json.Unmarshal(raw, &osv); err != nil {
		return intel.Record{}, StatusEcosystemMiss
	}
	if osv.ID == "" || len(osv.Affected) == 0 {
		return intel.Record{}, StatusEcosystemMiss
	}
	var aff *osvAffected
	for i := range osv.Affected {
		if canonicaliseEcosystem(osv.Affected[i].Package.Ecosystem) == canon {
			aff = &osv.Affected[i]
			break
		}
	}
	if aff == nil {
		return intel.Record{}, StatusEcosystemMiss
	}
	if osv.Withdrawn != "" {
		return intel.Record{}, StatusWithdrawn
	}
	signal := hasHighConfidenceSignal(osv)
	if len(aff.Versions) == 0 {
		// Mirrors Import: the range channels (all-versions entries and
		// npm bounded ranges) require the firm malicious-package
		// signal, never the keyword gate - a keyword false positive
		// on a range flags every version below the bound. A record
		// with neither versions nor ranges has nothing range support
		// could unlock, so it stays in the plain ranges-only bucket
		// regardless of signal.
		if signal && len(aff.Ranges) > 0 {
			rec := intel.Record{
				ID:         osv.ID,
				Aliases:    append([]string(nil), osv.Aliases...),
				Ecosystem:  canon,
				Name:       aff.Package.Name,
				Kind:       intel.KindMalicious,
				Summary:    pickSummary(osv),
				Ranges:     convertRanges(aff.Ranges),
				References: extractReferenceURLs(osv.References),
			}
			if rangesAllVersionsShape(aff.Ranges) {
				// Mirrors Import: these ship as compact
				// Snapshot.AllVersions entries.
				return rec, StatusAllVersionsKept
			}
			rec.Ranges = evaluableRanges(rec.Ranges)
			if len(rec.Ranges) == 0 {
				// Every range converted to nothing (empty events,
				// limit-only): the record asserts nothing usable and
				// Import drops it.
				return intel.Record{}, StatusRangesOnly
			}
			if canon == "npm" {
				// npm bounded ranges ship as full Records (C3-B):
				// the matcher's semver range evaluation covers them.
				return rec, StatusKept
			}
			// Bounded malicious ranges outside npm: still dropped
			// (the range gate is npm-only).
			return rec, StatusRangesOnlyMalicious
		}
		return intel.Record{}, StatusRangesOnly
	}
	versions := admittedExactVersions(osv, canon, *aff, signal)
	if len(versions) == 0 {
		return intel.Record{}, StatusNeither
	}
	return intel.Record{
		ID:         osv.ID,
		Aliases:    append([]string(nil), osv.Aliases...),
		Ecosystem:  canon,
		Name:       aff.Package.Name,
		Kind:       intel.KindMalicious,
		Summary:    pickSummary(osv),
		Versions:   append([]string(nil), versions...),
		References: extractReferenceURLs(osv.References),
	}, StatusKept
}

// SortAndDedupeAllVersions sorts entries (ecosystem, name, ID) and
// removes duplicates, mirroring SortRecords' reproducible-build role
// for the all_versions section. Exported for the snapshot generator.
func SortAndDedupeAllVersions(in []intel.AllVersionsEntry) []intel.AllVersionsEntry {
	sort.SliceStable(in, func(i, j int) bool {
		a, b := in[i], in[j]
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.ID < b.ID
	})
	return dedupeAllVersions(in)
}

// evaluableRanges keeps only ranges whose Type the matcher's semver
// engine can evaluate (SEMVER / ECOSYSTEM); a GIT or unknown-typed
// range would import as dead data the matcher silently skips.
func evaluableRanges(in []intel.VersionRange) []intel.VersionRange {
	var out []intel.VersionRange
	for _, r := range in {
		switch strings.ToUpper(strings.TrimSpace(r.Type)) {
		case "SEMVER", "ECOSYSTEM":
			out = append(out, r)
		}
	}
	return out
}

// dedupeAllVersions removes consecutive duplicates from a sorted
// entry slice (same ID, ecosystem, name).
func dedupeAllVersions(in []intel.AllVersionsEntry) []intel.AllVersionsEntry {
	if len(in) < 2 {
		return in
	}
	out := in[:1]
	for _, e := range in[1:] {
		last := out[len(out)-1]
		if e != last {
			out = append(out, e)
		}
	}
	return out
}

// buildEcosystemFilter returns a set keyed by the canonical
// ecosystem identifier (matcher.go conventions). A nil return means
// "do not filter".
//
// Unsupported / mistyped ecosystems are an error rather than a
// silent drop. A typo like `--ecosystem npmm` previously produced an
// empty filter that swallowed every record; releasing on that path
// would ship a 0-record snapshot for the affected ecosystem and the
// CLI would still exit successfully. Errors here surface to the
// importer and the CLI's exit code.
func buildEcosystemFilter(allowed []string) (map[string]struct{}, error) {
	if len(allowed) == 0 {
		return nil, nil
	}
	out := make(map[string]struct{}, len(allowed))
	for _, e := range allowed {
		canon := canonicaliseEcosystem(e)
		if canon == "" {
			return nil, fmt.Errorf("osvimport: unsupported ecosystem %q (supported: %s)", e, intel.SupportedEcosystemsHint())
		}
		out[canon] = struct{}{}
	}
	return out, nil
}

// canonicaliseEcosystem maps the assorted spellings OSV uses (and
// that callers pass) onto the matcher's canonical identifiers via
// the intel package's ecosystem registry. OSV publishes "npm",
// "PyPI", "Go", "crates.io", "Packagist", "RubyGems", "Maven",
// "NuGet" with exact casing; the registry also accepts the
// lower-case aliases and human-friendly synonyms (`python`,
// `golang`, `rust`, `java`, `dotnet`, ...).
func canonicaliseEcosystem(raw string) string {
	return intel.CanonicaliseEcosystem(raw)
}

// hasHighConfidenceSignal returns true when the record carries a
// firm "this is malicious" marker that does not rely on free-form
// text:
//
//   - The ID starts with MAL- (OSV's malicious-package namespace).
//   - DatabaseSpecific holds a top-level malicious-packages-origins
//     array with a nonempty source, as populated by OpenSSF.
func hasHighConfidenceSignal(osv osvRecord) bool {
	if strings.HasPrefix(osv.ID, "MAL-") {
		return true
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(osv.DatabaseSpecific, &fields) != nil {
		return false
	}
	var origins []struct {
		Source string `json:"source"`
	}
	if json.Unmarshal(fields["malicious-packages-origins"], &origins) != nil {
		return false
	}
	for _, origin := range origins {
		if strings.TrimSpace(origin.Source) != "" {
			return true
		}
	}
	return false
}

// Reviewed GitHub CWE-506 explicitly identifies embedded malicious code, unlike
// prose about exploiting otherwise legitimate software. Keep this exact-only;
// the range channels retain their existing MAL/OpenSSF source requirement.
func admittedExactVersions(osv osvRecord, eco string, aff osvAffected, sourceSignal bool) []string {
	if sourceSignal {
		return aff.Versions
	}
	var fields map[string]json.RawMessage
	if strings.HasPrefix(osv.ID, "GHSA-") && json.Unmarshal(osv.DatabaseSpecific, &fields) == nil {
		var reviewed bool
		var cwes []string
		if json.Unmarshal(fields["github_reviewed"], &reviewed) == nil && reviewed && json.Unmarshal(fields["cwe_ids"], &cwes) == nil {
			for _, cwe := range cwes {
				if cwe == "CWE-506" {
					return aff.Versions
				}
			}
		}
	}
	return intel.ReviewedOSVVersions(osv.ID, eco, aff.Package.Name, aff.Versions)
}

// pickSummary returns the most informative single-line text for a
// record: Summary if non-empty, otherwise the first line of Details.
// The runtime terminal output uses this as the "this is why we
// flagged it" line under each finding.
func pickSummary(osv osvRecord) string {
	if osv.Summary != "" {
		return osv.Summary
	}
	if osv.Details == "" {
		return ""
	}
	// Return the first line so the terminal output stays compact.
	if idx := strings.Index(osv.Details, "\n"); idx >= 0 {
		return strings.TrimSpace(osv.Details[:idx])
	}
	return strings.TrimSpace(osv.Details)
}

// extractReferenceURLs flattens the OSV reference array into a
// list of URLs. Order is preserved so the generator emits a
// deterministic output.
func extractReferenceURLs(refs []osvReference) []string {
	if len(refs) == 0 {
		return nil
	}
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		if r.URL != "" {
			out = append(out, r.URL)
		}
	}
	return out
}
