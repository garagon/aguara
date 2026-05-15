package intel

import "strings"

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
type Matcher struct {
	// byKey indexes records by `ecosystem + "\x00" + normName`.
	// A separator that can never appear in a package name keeps
	// the key collision-free without a real composite-key type.
	byKey map[string][]Record
}

// NewMatcher builds a Matcher from the given snapshots. Records
// from later snapshots do not override earlier ones; all records
// are indexed and returned. Withdrawn records are excluded at
// index time so MatchPackage never has to filter them.
//
// Duplicate records are collapsed by (ecosystem, name, version,
// record.ID) so an entry that appears in both the manual snapshot
// and the OSV snapshot only produces one Match.
func NewMatcher(snapshots ...Snapshot) *Matcher {
	m := &Matcher{byKey: make(map[string][]Record)}
	seen := make(map[string]struct{})
	for _, snap := range snapshots {
		for _, rec := range snap.Records {
			if rec.Withdrawn {
				continue
			}
			key := indexKey(rec.Ecosystem, rec.Name)
			if key == "" {
				continue
			}
			// Dedup: an entry that appears in both the manual
			// snapshot and the OSV snapshot at the same
			// (ecosystem, name, version, id) tuple counts once.
			for _, v := range versionSet(rec) {
				dedupKey := key + "\x00" + v + "\x00" + rec.ID
				if _, ok := seen[dedupKey]; ok {
					continue
				}
				seen[dedupKey] = struct{}{}
			}
			m.byKey[key] = append(m.byKey[key], rec)
		}
	}
	return m
}

// versionSet returns the set of exact versions a record covers.
// Used only by NewMatcher's dedup path; MatchPackage walks
// Record.Versions directly.
func versionSet(rec Record) []string {
	if len(rec.Versions) == 0 {
		// Ensures a records-with-no-versions record still produces
		// at least one dedup key so identical no-version entries
		// from two sources collapse correctly.
		return []string{""}
	}
	return rec.Versions
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
	if m == nil || len(m.byKey) == 0 {
		return nil
	}
	key := indexKey(in.Ecosystem, in.Name)
	if key == "" {
		return nil
	}
	candidates := m.byKey[key]
	if len(candidates) == 0 {
		return nil
	}
	var out []Match
	for _, rec := range candidates {
		if !versionMatches(rec, in.Version) {
			continue
		}
		out = append(out, Match{Record: rec, Path: in.Path})
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
// canonical value. The check command, OSV importer, and manual
// adapter may all use slightly different casing or aliases; this
// function is the one place that has to know about them.
func normalizeEcosystem(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "npm":
		return EcosystemNPM
	case "pypi", "python":
		return EcosystemPyPI
	default:
		// Unknown ecosystems are preserved as-is (lower-cased)
		// so future ecosystems wire in additively without code
		// changes here. They simply will not match anything
		// until records ship for them.
		return strings.ToLower(strings.TrimSpace(s))
	}
}

// normalizeName applies ecosystem-specific name canonicalisation.
//
//   - npm: trim whitespace, preserve case and scope.
//   - PyPI: PEP 503 -- lower-case, then collapse runs of [-_.]
//     into a single '-'.
//
// Anything else falls back to a whitespace trim + lower-case,
// which is the safe-default behaviour for ecosystems we have not
// taught the package about yet.
func normalizeName(ecosystem, name string) string {
	name = strings.TrimSpace(name)
	switch ecosystem {
	case EcosystemNPM:
		return name
	case EcosystemPyPI:
		return PEP503Normalize(name)
	default:
		return strings.ToLower(name)
	}
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
