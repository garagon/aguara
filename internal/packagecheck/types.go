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
}

// EcosystemResult is the per-Target summary surfaced in
// CheckResult.Ecosystems. The shape is stable across ecosystems so
// the JSON contract does not branch per parser.
//
// FindingsCount sums to len(CheckResult.Findings) only for findings
// produced by packagecheck. Existing incident-level findings
// (npm / PyPI) are NOT reflected in the per-target Ecosystems slice
// during v0.17.x; the slice describes the packagecheck discovery
// surface only.
type EcosystemResult struct {
	Ecosystem     string `json:"ecosystem"`
	Path          string `json:"path"`
	Source        string `json:"source"`
	PackagesRead  int    `json:"packages_read"`
	FindingsCount int    `json:"findings_count"`
}
