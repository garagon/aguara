package intel

import (
	"strings"

	"github.com/garagon/aguara/internal/intel/versions"
)

// MatchInput describes a single installed package to look up in
// one or more snapshots. Path is optional metadata that the caller
// passes through unchanged so the Match result keeps its on-disk
// provenance.
type MatchInput struct {
	Ecosystem string
	Name      string
	Version   string
	Path      string
}

// Match is the resolved result of a MatchPackage hit. Record is a
// pointer into the snapshot the matcher was built with; callers
// must treat it as read-only.
type Match struct {
	Record Record
	Path   string
}

// Matcher resolves MatchInput against one or more snapshots and
// returns all matching records. It builds an in-memory index keyed
// by ecosystem+normalised-name so MatchPackage runs in O(1) on the
// number of records per package, not O(N) on the whole snapshot.
//
// The matcher is intentionally narrow: it does not consult Ranges
// in the first implementation. Records that only carry ranges
// (no exact Versions) cannot match yet; this is by design so a
// half-correct semver parser never produces a wrong answer. The
// OSV importer must populate Versions for every record it ships
// or drop the record.
//
// Records are stored as pointers so the version-merge path in
// NewMatcher can extend the affected-version list of an already-
// indexed advisory without having to rebuild the index. The
// pointers are never mutated after NewMatcher returns; MatchPackage
// reads them concurrently and is safe to call from multiple
// goroutines.
type Matcher struct {
	// byKey indexes records by `ecosystem + "\x00" + normName`.
	// A separator that can never appear in a package name keeps
	// the key collision-free without a real composite-key type.
	byKey map[string][]*Record
	// allVersions maps indexKey(ecosystem, name) to the advisory IDs
	// of its AllVersionsEntry rows: every version of the package is
	// malicious, no version comparison needed. Distinct advisory IDs
	// are all kept (mirroring the Records contract: separate IDs are
	// useful provenance for cross-source correlation); duplicates are
	// collapsed and tombstones (withdrawn records with the same ID)
	// remove individual IDs.
	allVersions map[string][]string
}

// NewMatcher builds a Matcher from the given snapshots. Withdrawn
// records are excluded at index time so MatchPackage never has to
// filter them.
//
// Duplicate-advisory merge: when the same advisory ID appears for
// the same (ecosystem, name) tuple in more than one snapshot (the
// documented manual + OSV refresh case), the affected-version set
// is unioned across snapshots and surfaced as a single Match. We
// keep the FIRST occurrence's other metadata (Summary, Severity,
// References, IOCs, Kind) so manual emergency advisories retain
// their display priority over later sources -- callers that load
// manual snapshots before OSV get the manual phrasing in the
// terminal output while still benefiting from any new affected
// versions OSV reports.
//
// Distinct advisory IDs at the same (ecosystem, name, version)
// tuple are kept separate: two records that share a compromise
// are useful provenance (e.g. one OSV ID, one Socket ID) and must
// both surface so cross-source correlation works.
func NewMatcher(snapshots ...Snapshot) *Matcher {
	m := &Matcher{
		byKey:       make(map[string][]*Record),
		allVersions: make(map[string][]string),
	}

	// First pass: collect tombstones. Any (ecosystem, name, ID)
	// tuple that has a Withdrawn record in any snapshot is dead --
	// even if an earlier snapshot ships the same ID as live, a
	// later "we retracted this advisory" record must override.
	// The two-pass walk means the tombstone fires regardless of
	// the order snapshots are passed to NewMatcher; a single-pass
	// "remove from byID/byKey on encounter" would only work if
	// the withdrawn record came strictly after the live one.
	tombstones := make(map[string]struct{})
	for _, snap := range snapshots {
		for _, rec := range snap.Records {
			if !rec.Withdrawn {
				continue
			}
			key := indexKey(rec.Ecosystem, rec.Name)
			if key == "" {
				continue
			}
			tombstones[key+"\x00"+rec.ID] = struct{}{}
		}
	}

	byID := make(map[string]*Record)
	for _, snap := range snapshots {
		for _, rec := range snap.Records {
			if rec.Withdrawn {
				continue
			}
			key := indexKey(rec.Ecosystem, rec.Name)
			if key == "" {
				continue
			}
			idKey := key + "\x00" + rec.ID
			if _, dead := tombstones[idKey]; dead {
				continue
			}
			if existing, ok := byID[idKey]; ok {
				existing.Versions = unionVersions(existing.Versions, rec.Versions)
				existing.Ranges = unionRanges(existing.Ranges, rec.Ranges)
				continue
			}
			// First occurrence: take a defensive copy so a later
			// merge cannot mutate the caller's snapshot slice. The
			// pointer is shared between byID and byKey so a merge
			// here is visible to MatchPackage without an index
			// rebuild.
			recCopy := rec
			recCopy.Versions = append([]string(nil), rec.Versions...)
			recCopy.Ranges = append([]VersionRange(nil), rec.Ranges...)
			byID[idKey] = &recCopy
			m.byKey[key] = append(m.byKey[key], &recCopy)
		}
	}

	// All-versions entries: distinct advisory IDs per (ecosystem,
	// name) are all kept, in snapshot order (manual-first), with
	// duplicates collapsed; a tombstone for the same (key, ID) kills
	// that ID just like it kills a record.
	seenEntry := make(map[string]struct{})
	for _, snap := range snapshots {
		for _, e := range snap.AllVersions {
			key := indexKey(e.Ecosystem, e.Name)
			if key == "" || e.ID == "" {
				continue
			}
			idKey := key + "\x00" + e.ID
			if _, dead := tombstones[idKey]; dead {
				continue
			}
			if _, dup := seenEntry[idKey]; dup {
				continue
			}
			seenEntry[idKey] = struct{}{}
			m.allVersions[key] = append(m.allVersions[key], e.ID)
		}
	}
	return m
}

// unionVersions returns a + b with duplicates removed. Order is
// preserved (a's elements first, then any new b elements) so the
// list a caller sees on a refresh is the manual list with any
// fresh OSV versions appended -- predictable for testing and
// terminal output.
func unionVersions(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, v := range a {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	for _, v := range b {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// MatchPackage returns every Record that affects the given
// (Ecosystem, Name, Version) tuple. The result is empty (nil) when
// nothing matches; callers can range over the slice unconditionally.
//
// Matching rules:
//
//   - Ecosystem must match exactly after normalisation.
//   - Name normalisation is ecosystem-specific:
//   - npm: case-sensitive, scope preserved.
//   - PyPI: PEP 503 -- lower-case and collapse [-_.]+ to a single '-'.
//   - Version must appear in Record.Versions exactly. Ranges are
//     deferred to a later PR; records with no Versions cannot match.
//   - Withdrawn records were excluded at index time and never appear.
//
// The result preserves the in.Path on every Match so terminal output
// can show the on-disk location without the caller threading it back
// through.
func (m *Matcher) MatchPackage(in MatchInput) []Match {
	if m == nil || (len(m.byKey) == 0 && len(m.allVersions) == 0) {
		return nil
	}
	key := indexKey(in.Ecosystem, in.Name)
	if key == "" {
		return nil
	}
	candidates := m.byKey[key]
	allowRanges := ecosystemSupportsRanges(normalizeEcosystem(in.Ecosystem))
	var out []Match
	for _, rec := range candidates {
		if rec == nil {
			continue
		}
		// Exact version match takes priority and is checked first, so
		// behavior for records that carry Versions is unchanged. Only
		// when the exact check misses do we consult ranges, and only
		// for ecosystems whose grammar the semver engine can evaluate.
		// A record matches at most once: the continue on exact match
		// means a record carrying both Versions and Ranges does not
		// produce two Match entries for one installed version.
		switch {
		case versionMatches(*rec, in.Version):
		case allowRanges && rangeMatches(*rec, in.Version):
		default:
			continue
		}
		out = append(out, Match{Record: *rec, Path: in.Path})
	}

	// All-versions entry: any installed version of this package is
	// malicious; no version comparison is involved. Skipped when a
	// full record with the same advisory ID already matched, so one
	// advisory never produces two findings.
	for _, id := range m.allVersions[key] {
		dup := false
		for _, mt := range out {
			if mt.Record.ID == id {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, Match{Record: synthesizeAllVersionsRecord(id, in), Path: in.Path})
		}
	}
	return out
}

// synthesizeAllVersionsRecord builds the user-facing record for an
// all-versions match. Summary and reference are derived from the
// advisory ID so the stored entry stays three strings.
func synthesizeAllVersionsRecord(id string, in MatchInput) Record {
	return Record{
		ID:        id,
		Ecosystem: normalizeEcosystem(in.Ecosystem),
		Name:      in.Name,
		Kind:      KindMalicious,
		Summary:   "Every version of " + in.Name + " is marked malicious (" + id + ").",
		References: []string{
			"https://osv.dev/vulnerability/" + id,
		},
	}
}

// ecosystemSupportsRanges reports whether MatchPackage will evaluate
// Record.Ranges for this normalized ecosystem. Range matching is
// enabled only for semver ecosystems the versions engine can evaluate.
// Phase 1 is npm only: every TrapDoor range-only record is npm, and
// npm version ordering is semver. crates.io is also semver and can be
// added here once it carries malicious range records; until then it
// stays out so range matching does not widen the matched surface with
// no current benefit. PyPI / Maven / Go are intentionally excluded
// because their grammars are not semver.
func ecosystemSupportsRanges(eco string) bool {
	return eco == EcosystemNPM
}

// rangeMatches reports whether version falls in any of the record's
// semver-evaluable ranges. Ranges whose Type the semver engine cannot
// order are skipped; a record with no evaluable range does not match.
func rangeMatches(rec Record, version string) bool {
	if len(rec.Ranges) == 0 {
		return false
	}
	semverRanges := make([]versions.Range, 0, len(rec.Ranges))
	for _, r := range rec.Ranges {
		if !isSemverRangeType(r.Type) {
			continue
		}
		semverRanges = append(semverRanges, versions.Range{
			Introduced:   r.Introduced,
			Fixed:        r.Fixed,
			LastAffected: r.LastAffected,
		})
	}
	if len(semverRanges) == 0 {
		return false
	}
	return versions.Affected(version, semverRanges)
}

// isSemverRangeType reports whether an OSV range Type can be evaluated
// by the semver engine. OSV uses "SEMVER" for semver ranges and
// "ECOSYSTEM" for ecosystem-defined ordering; for the npm-only phase
// both are semver-ordered. Any other type (e.g. "GIT", "PEP440") is
// not evaluable here and contributes no match.
func isSemverRangeType(t string) bool {
	switch strings.ToUpper(strings.TrimSpace(t)) {
	case "SEMVER", "ECOSYSTEM":
		return true
	default:
		return false
	}
}

// unionRanges returns a + b with duplicate ranges removed, preserving
// order (a first, then any new entries from b). VersionRange is a
// comparable struct so equality dedup is exact. Used when the same
// advisory ID appears across snapshots (manual + OSV refresh) so the
// merged record carries every affected range, not just the first
// snapshot's.
func unionRanges(a, b []VersionRange) []VersionRange {
	if len(b) == 0 {
		return a
	}
	seen := make(map[VersionRange]struct{}, len(a)+len(b))
	out := make([]VersionRange, 0, len(a)+len(b))
	for _, r := range a {
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}
	for _, r := range b {
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}
	return out
}

// indexKey produces the byKey index entry for an (ecosystem, name)
// pair. Returns "" when either field is missing so the empty key
// can never collide with a real entry.
func indexKey(ecosystem, name string) string {
	eco := normalizeEcosystem(ecosystem)
	if eco == "" || name == "" {
		return ""
	}
	return eco + "\x00" + normalizeName(eco, name)
}

// normalizeEcosystem maps assorted ecosystem spellings to the
// canonical OSV bucket key via the registry in ecosystem.go.
// Unknown ecosystems are preserved as-is (lower-cased) so future
// ecosystems wire in additively here; they simply will not match
// anything until the registry knows about them.
func normalizeEcosystem(s string) string {
	if canon := CanonicaliseEcosystem(s); canon != "" {
		return canon
	}
	return strings.ToLower(strings.TrimSpace(s))
}

// normalizeName applies ecosystem-specific name canonicalisation
// via the registry. Each EcosystemSpec.NormalizePackageName carries
// the rule: PEP 503 for PyPI, lower-case + trim for the case-folding
// ecosystems (Cargo / Packagist / RubyGems / NuGet), case-preserving
// trim for npm / Go / Maven. Unknown ecosystems fall back to
// lower-case + trim, the safe default for ecosystems we have not
// taught the package about yet.
func normalizeName(ecosystem, name string) string {
	if spec, ok := lookupSpec(ecosystem); ok && spec.NormalizePackageName != nil {
		return spec.NormalizePackageName(name)
	}
	return nameLowerTrim(name)
}

// PEP503Normalize implements the simple form of PEP 503 used by
// OSV.dev: lower-case and collapse [-_.]+ to '-'. Exported so other
// packages that need to compare PyPI names can reuse it without
// importing matcher internals; the function is pure and safe to
// call concurrently.
func PEP503Normalize(name string) string {
	name = strings.ToLower(name)
	var b strings.Builder
	b.Grow(len(name))
	lastWasSep := false
	for _, r := range name {
		switch r {
		case '-', '_', '.':
			if !lastWasSep {
				b.WriteByte('-')
				lastWasSep = true
			}
		default:
			b.WriteRune(r)
			lastWasSep = false
		}
	}
	// Strip a trailing separator that the loop might have emitted
	// for names ending in `.` or `_` (rare, but cheap to handle).
	out := b.String()
	if strings.HasSuffix(out, "-") {
		out = strings.TrimRight(out, "-")
	}
	return out
}

// versionMatches reports whether v is in rec.Versions. The check is
// a literal equality so callers that prefix with `v` (Go module
// style) or pad with leading zeroes do not silently match. The OSV
// importer is responsible for producing canonicalised version
// strings.
func versionMatches(rec Record, v string) bool {
	for _, candidate := range rec.Versions {
		if candidate == v {
			return true
		}
	}
	return false
}
