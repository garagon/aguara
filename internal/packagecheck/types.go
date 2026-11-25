// Package packagecheck is the layered ecosystem-discovery + parser
// + matcher orchestration plane Aguara uses to check declared /
// installed packages against the threat-intel matcher.
//
// It deliberately stays narrow in this first cut: discovery for Go
// (go.sum / go.mod), parsing that does not execute external tools
// or touch the network, and a runner that fans each discovered
// target through intel.Matcher and produces both the per-target
// EcosystemResult summary surfaced in JSON and the flat Hit slice
// the CLI converts into incident.Finding entries.
//
// The existing incident.Check / incident.CheckNPM paths stay
// intact; this package is the new substrate the multi-ecosystem
// expansion will migrate them onto over v0.17.x.
package packagecheck

// PackageRef is one declared / installed dependency a parser
// extracts from a lockfile or installed-package tree. Path / Source
// preserve provenance so the runner's Hit retains the matched
// file's on-disk location.
type PackageRef struct {
	// Ecosystem is the canonical OSV bucket key
	// (intel.EcosystemGo, intel.EcosystemNPM, ...).
	Ecosystem string
	// Name is the canonical package identifier in the ecosystem
	// (module path for Go, scoped name for npm, etc.). The parser
	// does NOT normalise the name; the matcher applies the
	// ecosystem-specific normalizer at lookup time.
	Name string
	// Version is the literal version string from the lockfile,
	// including any leading "v" Go modules carry. The matcher
	// compares against intel.Record.Versions verbatim.
	Version string
	// Path is the absolute or repo-relative path the parser read
	// the ref from (the lockfile, the .dist-info dir, etc.).
	Path string
	// Source is the basename of the file the parser consumed
	// ("go.sum", "go.mod", "package-lock.json"). Used by the
	// per-target EcosystemResult summary so monorepo output
	// distinguishes services/api/go.sum from workers/scraper/go.sum.
	Source string
	// Line is the 1-based line of the entry in Path when the format
	// has a meaningful one (requirements files, TOML lockfiles); 0
	// otherwise.
	Line int
	// Group is the dependency group or category the file assigns to
	// the entry ("dev", "develop", "constraint"); empty when the format
	// does not record one per entry or the entry is a main dependency.
	Group string
	// Unpinned marks an entry that is present without one exact
	// version (for example `requests>=2` in requirements.txt). Version
	// is empty and Constraint keeps the declared specifier. The runner
	// matches such entries only against advisories that cover every
	// version of the package; it never guesses a version.
	Unpinned   bool
	Constraint string
	// ArbitraryEquality marks a version pinned with `===` in a pip
	// requirement, which pip compares as a string, not as a PEP 440
	// version (see intel.MatchInput.ArbitraryEquality).
	ArbitraryEquality bool
	// GraphOnly marks a version a lockfile records only as part of
	// dependency resolution, not as installed or built: a go.sum entry
	// with a `/go.mod` hash and no zip hash, that go.mod does not
	// require. It is matched only against advisories that cover every
	// version of the package.
	GraphOnly bool
}

// Target is one discovery anchor under the scanned root. Discovery
// emits one Target per lockfile, so a monorepo with two Go modules
// yields two Targets and the per-target EcosystemResult slice keeps
// each entry visible.
type Target struct {
	// Ecosystem is the canonical OSV bucket key the parser will
	// emit for refs found in this lockfile.
	Ecosystem string
	// Path is the absolute or repo-relative path to the lockfile.
	Path string
	// Source is the lockfile basename ("go.sum", "go.mod").
	Source string
	// Root is the project directory the discovery walk started from.
	// Requirements-file includes (-r / -c) are followed only inside
	// it. Empty means the directory that contains Path.
	Root string
}

// UnresolvedInclude is a requirements-file -r / -c include that pip
// would read but the check did not, so any pin in it went unchecked.
type UnresolvedInclude struct {
	// Path and Line locate the include directive.
	Path string `json:"path"`
	Line int    `json:"line"`
	// Argument is the include as written, with URL credentials redacted.
	Argument string `json:"argument"`
	// Reason is one of the UnresolvedInclude* constants.
	Reason string `json:"reason"`
}

// Why an include was not read.
const (
	UnresolvedIncludeURL      = "url"
	UnresolvedIncludeOutside  = "outside_project"
	UnresolvedIncludeMissing  = "missing"
	UnresolvedIncludeVariable = "environment_variable"
)

// EcosystemResult is the per-Target summary surfaced in
// CheckResult.Ecosystems. The shape is stable across ecosystems so
// the JSON contract does not branch per parser.
//
// FindingsCount sums to len(CheckResult.Findings) only for findings
// produced by packagecheck. Existing incident-level findings
// (npm / PyPI) are NOT reflected in the per-target Ecosystems slice
// during v0.17.x; the slice describes the packagecheck discovery
// surface only.
//
// Unpinned and UnresolvedIncludes are additive and omitted when zero.
// Unpinned counts entries (included in PackagesRead) that declare a
// package without one exact version, so only advisories covering every
// version could be matched for them. UnresolvedIncludes counts
// requirements-file includes that were not read: a URL, a path outside
// the project, or a missing file.
type EcosystemResult struct {
	Ecosystem          string `json:"ecosystem"`
	Path               string `json:"path"`
	Source             string `json:"source"`
	PackagesRead       int    `json:"packages_read"`
	FindingsCount      int    `json:"findings_count"`
	Unpinned           int    `json:"unpinned,omitempty"`
	UnresolvedIncludes int    `json:"unresolved_includes,omitempty"`
}
