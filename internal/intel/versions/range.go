package versions

// Range is one OSV affected range, reduced to its version bounds. It
// mirrors the bound fields of intel.VersionRange but is defined here so
// this package carries no dependency on internal/intel (which imports
// this package). The OSV range Type is deliberately absent: the caller
// must only construct a Range from a semver-compatible OSV range.
//
// OSV semantics:
//   - Introduced: inclusive lower bound. "" means OSV gave no
//     introduced event (no lower bound). "0" is OSV's sentinel for
//     "from the beginning of the version line" and is also treated as
//     no lower bound (so it matches every version, including
//     prereleases).
//   - Fixed: exclusive upper bound.
//   - LastAffected: inclusive upper bound.
//
// A range carries at most one upper bound. A Fixed and a LastAffected
// on the same range, or a range with no bound at all, is malformed and
// matches nothing.
type Range struct {
	Introduced   string
	Fixed        string
	LastAffected string
}

// Affected reports whether version falls inside any of the ranges
// (ranges are ORed, matching OSV semantics where a record's affected
// entry may list several ranges). It returns false when version cannot
// be parsed as semver, so a caller can pass an arbitrary installed
// version string safely.
func Affected(version string, ranges []Range) bool {
	v, ok := Parse(version)
	if !ok {
		return false
	}
	for _, r := range ranges {
		if r.contains(v) {
			return true
		}
	}
	return false
}

// contains reports whether v is inside this single range.
func (r Range) contains(v Version) bool {
	// A range with no bounds at all carries no information; treat it as
	// malformed rather than "matches everything" so a garbage record
	// cannot flag every version.
	if r.Introduced == "" && r.Fixed == "" && r.LastAffected == "" {
		return false
	}
	// A range cannot have both an exclusive and an inclusive upper
	// bound; that event sequence is malformed.
	if r.Fixed != "" && r.LastAffected != "" {
		return false
	}

	// Lower bound. "" and the "0" sentinel both mean no lower bound.
	if r.Introduced != "" && r.Introduced != "0" {
		intro, ok := Parse(r.Introduced)
		if !ok {
			return false
		}
		if v.Compare(intro) < 0 {
			return false
		}
	}

	// Upper bound: Fixed is exclusive, LastAffected is inclusive.
	switch {
	case r.Fixed != "":
		fixed, ok := Parse(r.Fixed)
		if !ok {
			return false
		}
		if v.Compare(fixed) >= 0 {
			return false
		}
	case r.LastAffected != "":
		last, ok := Parse(r.LastAffected)
		if !ok {
			return false
		}
		if v.Compare(last) > 0 {
			return false
		}
	}

	return true
}
