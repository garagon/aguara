// Package osvimport converts OSV.dev JSON dumps into intel.Snapshot
// values that the runtime matcher can consume.
//
// Scope is deliberately narrow: only high-confidence malicious or
// compromised package records survive the filter. Records without
// an exact affected-version list are dropped, because the runtime
// matcher refuses to consult ranges until a tested semver / PEP 440
// layer lands. A wrong match is worse than no match.
//
// This package is pure: it does no I/O of its own. ImportFromZip
// (in zip.go) is a small helper that reads OSV's all.zip dumps and
// feeds Import. RenderGoSource (in render.go) serialises the
// resulting snapshot back into Go source so it can be compiled into
// the binary as the embedded snapshot.
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
// (MAL- IDs, OpenSSF malicious-packages source, or a high-confidence
// keyword + exact versions).
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
//   - References lists URLs / publishings; we use them only to feed
//     the keyword scanner because OSV's free-form text is the only
//     place a "credential exfiltration" hint actually appears.
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
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvReference struct {
	Type string `json:"type,omitempty"`
	URL  string `json:"url,omitempty"`
}

// highConfidenceKeywords is the conservative keyword list the
// filter consults for records that do NOT come from a known-good
// source (MAL- ID or OpenSSF Malicious Packages). The list is small
// on purpose: a longer list pulls in generic-CVE noise (e.g. "DoS",
// "vulnerable to") that does not belong in the malicious-package
// snapshot. New keywords should only be added when the
// TestOSVImporterDropsGenericCVERecords baseline keeps holding.
var highConfidenceKeywords = []string{
	"malicious package",
	"malicious npm package",
	"malicious python package",
	"compromised package",
	"credential stealing",
	"credential exfiltration",
	"typosquat malware",
	"install script malware",
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
		SchemaVersion: intel.CurrentSchemaVersion,
		GeneratedAt:   opts.GeneratedAt,
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
		rec, ok := convertOSVRecord(b, ecoFilter)
		if !ok {
			continue
		}
		snap.Records = append(snap.Records, rec...)
	}

	// Stable order for reproducible builds: ecosystem, name, ID.
	// Without this the embedded snapshot would re-shuffle on every
	// regeneration even when the upstream OSV slice is identical.
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
func convertOSVRecord(raw []byte, ecoFilter map[string]struct{}) ([]intel.Record, bool) {
	var osv osvRecord
	if err := json.Unmarshal(raw, &osv); err != nil {
		// Malformed record: drop rather than abort the whole
		// import. A single bad row in a 100k-record OSV dump
		// must not deny-of-service the rest of the snapshot.
		return nil, false
	}
	if osv.ID == "" || len(osv.Affected) == 0 {
		return nil, false
	}

	// A withdrawn-in-OSV record passes through as a withdrawn
	// intel.Record so the matcher's tombstone path retracts any
	// earlier live copy from another source. The tombstone keys
	// off (ecosystem, name, ID) only, so a withdrawn record does
	// not need to satisfy the empty-versions or signal/keyword
	// gates that live records do.
	withdrawn := osv.Withdrawn != ""

	signal := hasHighConfidenceSignal(osv)
	keywordHit := hasKeywordMatch(osv)

	var out []intel.Record
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
		// and the signal/keyword gate. They exist purely so the
		// matcher can tombstone an earlier live copy with the
		// same advisory ID; if we filter them out here, the live
		// copy keeps matching forever after the retraction.
		if !withdrawn {
			if len(aff.Versions) == 0 {
				// Runtime matcher consults exact Versions only;
				// a ranges-only live record is unreachable.
				// Skip rather than emit dead data.
				continue
			}
			// Filter: keep when there is a high-confidence
			// source signal, OR a keyword hit on the free-form
			// text. The "exact versions present" check above
			// gates both paths.
			if !signal && !keywordHit {
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
	if len(out) == 0 {
		return nil, false
	}
	return out, true
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
	// StatusNeither: the record has exact versions but fails both
	// the high-confidence signal gate (MAL- prefix / OpenSSF
	// origin) and the keyword gate. CVE-flavoured records land
	// here and do not belong in a malicious-package snapshot.
	StatusNeither
	// StatusKept: the record survives the filter and becomes an
	// intel.Record in the snapshot.
	StatusKept
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
	if len(aff.Versions) == 0 {
		return intel.Record{}, StatusRangesOnly
	}
	if !hasHighConfidenceSignal(osv) && !hasKeywordMatch(osv) {
		return intel.Record{}, StatusNeither
	}
	return intel.Record{
		ID:         osv.ID,
		Aliases:    append([]string(nil), osv.Aliases...),
		Ecosystem:  canon,
		Name:       aff.Package.Name,
		Kind:       intel.KindMalicious,
		Summary:    pickSummary(osv),
		Versions:   append([]string(nil), aff.Versions...),
		References: extractReferenceURLs(osv.References),
	}, StatusKept
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
//   - DatabaseSpecific holds an `malicious-packages-origins` field,
//     which OpenSSF Malicious Packages populates.
//
// Either signal short-circuits the keyword scan so MAL- entries
// with sparse free-form text still survive.
func hasHighConfidenceSignal(osv osvRecord) bool {
	if strings.HasPrefix(osv.ID, "MAL-") {
		return true
	}
	if len(osv.DatabaseSpecific) > 0 {
		// We do not fully unmarshal database_specific; a simple
		// substring check on the raw bytes is enough to detect
		// the OpenSSF source without owning their schema.
		if strings.Contains(string(osv.DatabaseSpecific), "malicious-packages-origins") {
			return true
		}
	}
	return false
}

// hasKeywordMatch returns true when summary, details, or any
// reference URL contains one of the high-confidence keywords. The
// match is case-insensitive substring; matching is intentionally
// narrow because the broader the keyword list, the more generic
// CVEs leak into the malicious-package snapshot.
//
// References are scanned because OSV advisories often point to a
// Socket / Snyk / vendor blog post whose URL slug carries the
// signal ("malicious-package-foo", "credential-stealing-bar") even
// when the summary text is a generic vulnerability sentence. Without
// scanning the URL, those records would silently drop.
func hasKeywordMatch(osv osvRecord) bool {
	for _, hay := range []string{osv.Summary, osv.Details} {
		if hay == "" {
			continue
		}
		lower := strings.ToLower(hay)
		for _, kw := range highConfidenceKeywords {
			if strings.Contains(lower, kw) {
				return true
			}
		}
	}
	for _, ref := range osv.References {
		if ref.URL == "" {
			continue
		}
		// URL slugs use `-`, `_`, and `/` as word separators
		// (`/blog/malicious-package-foo-bar`). Normalise to
		// spaces so the keyword scan can match phrases like
		// "malicious package" against the slug form.
		normalised := strings.ToLower(ref.URL)
		for _, sep := range []string{"-", "_", "/"} {
			normalised = strings.ReplaceAll(normalised, sep, " ")
		}
		for _, kw := range highConfidenceKeywords {
			if strings.Contains(normalised, kw) {
				return true
			}
		}
	}
	return false
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
