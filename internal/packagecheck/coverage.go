package packagecheck

import (
	"encoding/json"

	"github.com/garagon/aguara/internal/intel"
)

// Coverage states which dependency evidence a check evaluated, so a
// result with no findings can be told apart from a result that read
// nothing. It is reported as `coverage` in check and audit JSON.
type Coverage struct {
	// PackageEvidence totals what was read, per ecosystem and source.
	PackageEvidence []EvidenceSummary `json:"package_evidence"`
	// UnsupportedEvidence lists dependency files that were found but
	// that Aguara cannot evaluate: none of their packages were checked.
	UnsupportedEvidence []UnsupportedEvidence `json:"unsupported_evidence"`
	// UnresolvedIncludes lists requirements -r / -c includes that a
	// read file names but the check did not read (a URL, a path outside
	// the project, an environment variable, a missing file). The file
	// that names them is in PackageEvidence; each one is also reported
	// once as a WARNING finding, which is what triage acts on.
	UnresolvedIncludes []UnresolvedInclude `json:"unresolved_includes"`
}

// EvidenceSummary totals the evidence read from one source kind
// (a lockfile name, "node_modules" or "site-packages") in one ecosystem.
// Per-file detail stays in the check's `ecosystems` array.
type EvidenceSummary struct {
	Ecosystem    string `json:"ecosystem"`
	Source       string `json:"source"`
	Targets      int    `json:"targets"`
	PackagesRead int    `json:"packages_read"`
	// Unpinned counts the PackagesRead entries declared without one
	// exact version: only advisories covering every version could be
	// matched for them. Omitted when zero, as in `ecosystems`.
	Unpinned int `json:"unpinned,omitempty"`
}

// UnsupportedEvidence is one dependency file whose packages the check did
// not evaluate: a format Aguara does not parse, an ecosystem it has no
// intelligence for, a requirements file under a name it does not read,
// or a manifest that declares dependencies without an evaluated lockfile.
type UnsupportedEvidence struct {
	// Path is the file as discovery saw it (joined to the checked root).
	Path string `json:"path"`
	// Kind names the file format, e.g. "deno.lock", "requirements.txt"
	// or "package.json".
	Kind string `json:"kind"`
	// Ecosystem is the package ecosystem the file describes.
	Ecosystem string `json:"ecosystem"`
	// Reason says why the file was not evaluated: one of the Reason*
	// constants (format_not_parsed, no_package_intelligence,
	// requirements_name_not_read, manifest_without_lockfile).
	Reason string `json:"reason,omitempty"`
	// NestedManifests counts, for a workspace root, the manifests below it
	// that a lockfile at the root would cover (its members and any other
	// project below it); they are not listed separately. Omitted when zero.
	NestedManifests int `json:"nested_manifests,omitempty"`
	// ExactPinsChecked counts the entries of the file (and of its
	// workspace members) that pin one exact registry version, which were
	// matched against exact-version intelligence. The rest of the file
	// was not evaluated. Omitted when zero.
	ExactPinsChecked int `json:"exact_pins_checked,omitempty"`

	// pins are the exact pins MatchPins checks.
	pins []PackageRef
}

// NoIntel reports whether Aguara has no malicious-package intelligence
// for the file's ecosystem at all, so a parser would not help: the file
// is unevaluated because nothing could be matched, not because of its
// format.
func (u UnsupportedEvidence) NoIntel() bool {
	return u.Ecosystem != "" && intel.CanonicaliseEcosystem(u.Ecosystem) == ""
}

// PinCount is the number of exact pins MatchPins would check for the entry.
func (u UnsupportedEvidence) PinCount() int { return len(u.pins) }

// MatchPins matches the exact pins of the listed entries against the
// matcher's exact-version and all-versions intelligence and returns the
// hits, one per (file, line, package, version), with each entry's
// ExactPinsChecked set. Only what a pin names is checked; everything else
// in those files stays unevaluated.
func MatchPins(m *intel.Matcher, entries []UnsupportedEvidence) []Hit {
	hits := []Hit{}
	if m == nil {
		return hits
	}
	seen := map[hitKey]bool{}
	for i := range entries {
		entries[i].ExactPinsChecked = len(entries[i].pins)
		for _, ref := range entries[i].pins {
			key := hitKey{name: ref.Ecosystem + "\x00" + ref.Name, version: ref.Version, path: ref.Path, line: ref.Line}
			if seen[key] {
				continue
			}
			seen[key] = true
			matches := m.MatchPackage(intel.MatchInput{
				Ecosystem:         ref.Ecosystem,
				Name:              ref.Name,
				Version:           ref.Version,
				Path:              ref.Path,
				ArbitraryEquality: ref.ArbitraryEquality,
			})
			if len(matches) == 0 {
				continue
			}
			hits = append(hits, Hit{Ref: ref, Record: matches[0].Record, AdvisoryIDs: advisoryIDs(matches)})
		}
	}
	return hits
}

// MarshalJSON keeps every array as `[]` rather than `null` when empty.
func (c Coverage) MarshalJSON() ([]byte, error) {
	if c.PackageEvidence == nil {
		c.PackageEvidence = []EvidenceSummary{}
	}
	if c.UnsupportedEvidence == nil {
		c.UnsupportedEvidence = []UnsupportedEvidence{}
	}
	if c.UnresolvedIncludes == nil {
		c.UnresolvedIncludes = []UnresolvedInclude{}
	}
	type alias Coverage
	return json.Marshal(alias(c))
}

// Evaluated reports whether any dependency evidence was read.
func (c Coverage) Evaluated() bool {
	return len(c.PackageEvidence) > 0
}

// SummarizeEvidence folds per-target results into one entry per
// (ecosystem, source), in order of first appearance.
func SummarizeEvidence(results []EcosystemResult) []EvidenceSummary {
	out := []EvidenceSummary{}
	index := map[[2]string]int{}
	for _, r := range results {
		key := [2]string{r.Ecosystem, r.Source}
		i, ok := index[key]
		if !ok {
			i = len(out)
			index[key] = i
			out = append(out, EvidenceSummary{Ecosystem: r.Ecosystem, Source: r.Source})
		}
		out[i].Targets++
		out[i].PackagesRead += r.PackagesRead
		out[i].Unpinned += r.Unpinned
	}
	return out
}
