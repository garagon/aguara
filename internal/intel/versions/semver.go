// Package versions is a small, dependency-free semver evaluator for
// OSV-style affected ranges. It answers one question: given a version
// string and a set of ranges, is the version affected?
//
// Scope and boundaries:
//
//   - Semver only. Parse implements Semantic Versioning 2.0.0
//     precedence (major.minor.patch, prerelease ordering, build
//     metadata ignored for precedence). PEP 440, Maven, and Go
//     pseudo-version grammars are out of scope; callers that hold a
//     non-semver ecosystem must not route through this package.
//   - Ecosystem-agnostic. This package does not know which ecosystems
//     are semver. The matcher owns the ecosystem -> grammar decision
//     and only calls Affected for semver ecosystems (npm, crates.io).
//     Keeping ecosystem knowledge out of here is also what lets this
//     package stay free of any dependency on internal/intel, which
//     imports it (the cycle would otherwise be intel -> versions ->
//     intel).
//   - Type-agnostic ranges. Range carries only the OSV event bounds,
//     not the OSV range Type. The matcher/importer is responsible for
//     passing only semver-compatible ranges; a record's PEP440 or
//     unknown-type range must be filtered out before it reaches here.
//   - Conservative. An unparseable version, an unparseable bound, or a
//     malformed range yields no match. A wrong match is worse than no
//     match: this engine gates malicious-package findings.
package versions

import "strings"

// Version is a parsed semver value. Build metadata is intentionally
// not retained: it does not participate in precedence.
type Version struct {
	major      int
	minor      int
	patch      int
	prerelease []string // dot-separated identifiers; empty for a release
}

// Parse parses a semver string. A single leading 'v' is accepted and
// stripped (so "v1.2.3" and "1.2.3" parse identically) because OSV and
// some ecosystems prefix versions with it. Build metadata (everything
// after '+') is discarded. Returns ok=false for anything that is not a
// numeric major.minor.patch core with optional prerelease.
func Parse(s string) (Version, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	if s == "" {
		return Version{}, false
	}
	// Drop build metadata: ignored for precedence.
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	// Split off the prerelease segment. A '-' marks a prerelease, which
	// must then be non-empty with non-empty dot-separated identifiers;
	// "1.2.3-" is malformed.
	var pre string
	hasPre := false
	if i := strings.IndexByte(s, '-'); i >= 0 {
		pre = s[i+1:]
		s = s[:i]
		hasPre = true
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return Version{}, false
	}
	maj, ok1 := atoiStrict(parts[0])
	min, ok2 := atoiStrict(parts[1])
	pat, ok3 := atoiStrict(parts[2])
	if !ok1 || !ok2 || !ok3 {
		return Version{}, false
	}
	v := Version{major: maj, minor: min, patch: pat}
	if hasPre {
		ids := strings.Split(pre, ".")
		for _, id := range ids {
			if id == "" {
				return Version{}, false // empty prerelease identifier (incl. trailing '-')
			}
		}
		v.prerelease = ids
	}
	return v, true
}

// Compare returns -1, 0, or +1 as v is less than, equal to, or greater
// than o, following Semver 2.0.0 precedence rules.
func (v Version) Compare(o Version) int {
	if c := cmpInt(v.major, o.major); c != 0 {
		return c
	}
	if c := cmpInt(v.minor, o.minor); c != 0 {
		return c
	}
	if c := cmpInt(v.patch, o.patch); c != 0 {
		return c
	}
	return comparePrerelease(v.prerelease, o.prerelease)
}

// comparePrerelease implements Semver 2.0.0 section 11: a version with
// a prerelease has lower precedence than the same version without one;
// identifiers are compared left to right, numeric identifiers
// numerically, alphanumeric lexically, numeric below alphanumeric, and
// a longer set of identifiers wins when all preceding are equal.
func comparePrerelease(a, b []string) int {
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) == 0: // a is a release, b is a prerelease -> a is greater
		return 1
	case len(b) == 0:
		return -1
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		if c := comparePrereleaseIdent(a[i], b[i]); c != 0 {
			return c
		}
	}
	return cmpInt(len(a), len(b))
}

func comparePrereleaseIdent(a, b string) int {
	an, aNum := atoiStrict(a)
	bn, bNum := atoiStrict(b)
	switch {
	case aNum && bNum:
		return cmpInt(an, bn)
	case aNum && !bNum:
		return -1 // numeric identifiers have lower precedence than alphanumeric
	case !aNum && bNum:
		return 1
	default:
		return strings.Compare(a, b)
	}
}

const maxInt = int(^uint(0) >> 1)

// atoiStrict parses a non-negative base-10 integer. It rejects empty
// input, signs, and any non-digit byte, so "+1", "-1", "1a", and ""
// all fail. This is stricter than strconv.Atoi on purpose: a core or
// numeric-prerelease identifier is digits only.
//
// It also rejects values that would overflow int. The accumulator
// would otherwise wrap (e.g. a major component above maxInt becoming
// negative), and since this gates malicious-package matching, a
// silently-wrapped version is treated as unparseable -> no match,
// rather than risking a wrong comparison.
func atoiStrict(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		d := int(c - '0')
		if n > (maxInt-d)/10 { // n*10 + d would overflow int
			return 0, false
		}
		n = n*10 + d
	}
	return n, true
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
