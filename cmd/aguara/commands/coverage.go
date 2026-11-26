package commands

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/garagon/aguara/internal/incident"
	"github.com/garagon/aguara/internal/output"
	"github.com/garagon/aguara/internal/packagecheck"
	"github.com/garagon/aguara/internal/scanner"
)

// AuditCoverage is audit's top-level statement of what it evaluated:
// the content scan's file count plus the package check's evidence. The
// nested check.coverage and scan.coverage blocks carry the same data.
type AuditCoverage struct {
	FilesScanned        int                                `json:"files_scanned"`
	PackageEvidence     []packagecheck.EvidenceSummary     `json:"package_evidence"`
	UnsupportedEvidence []packagecheck.UnsupportedEvidence `json:"unsupported_evidence"`
	UnresolvedIncludes  []packagecheck.UnresolvedInclude   `json:"unresolved_includes"`
}

// MarshalJSON keeps every array as `[]` rather than `null` when empty.
func (c AuditCoverage) MarshalJSON() ([]byte, error) {
	if c.PackageEvidence == nil {
		c.PackageEvidence = []packagecheck.EvidenceSummary{}
	}
	if c.UnsupportedEvidence == nil {
		c.UnsupportedEvidence = []packagecheck.UnsupportedEvidence{}
	}
	if c.UnresolvedIncludes == nil {
		c.UnresolvedIncludes = []packagecheck.UnresolvedInclude{}
	}
	type alias AuditCoverage
	return json.Marshal(alias(c))
}

// checkCoverage builds the coverage block for a finished check. A file
// the check read is never reported as unsupported: neither a parsed
// target nor a requirements file reached through an include (run may be
// nil when no lockfile was parsed). Paths are compared with symlinks
// resolved.
func checkCoverage(plan checkPlan, result *incident.CheckResult, run *packagecheck.RunResult) *packagecheck.Coverage {
	read := map[string]bool{}
	for _, e := range result.Ecosystems {
		read[packagecheck.ResolvedPath(e.Path)] = true
	}
	if run != nil {
		for _, f := range run.ReadFiles {
			read[f] = true
		}
	}
	unsupported := []packagecheck.UnsupportedEvidence{}
	for _, u := range plan.unsupported {
		if !read[packagecheck.ResolvedPath(u.Path)] {
			unsupported = append(unsupported, u)
		}
	}
	if run != nil {
		// Requirements files whose syntax the parser does not read.
		unsupported = append(unsupported, run.Unparsed...)
	}
	// Manifests that declare dependencies no lockfile covers: an install
	// would resolve versions the check never saw.
	locks := packagecheck.CoveringLockfiles(plan.packagecheckTargets, unsupported)
	var reqs []packagecheck.RequirementsEvidence
	if run != nil {
		reqs = run.Requirements
	}
	unsupported = append(unsupported, packagecheck.ManifestsWithoutLockfile(plan.discoveryRoot, plan.manifests, locks, reqs)...)
	includes := []packagecheck.UnresolvedInclude{}
	if run != nil {
		includes = append(includes, run.UnresolvedIncludes...)
	}
	return &packagecheck.Coverage{
		PackageEvidence:     packagecheck.SummarizeEvidence(result.Ecosystems),
		UnsupportedEvidence: unsupported,
		UnresolvedIncludes:  includes,
	}
}

// auditCoverage combines the two halves of an audit.
func auditCoverage(check *incident.CheckResult, scan *scanner.ScanResult) AuditCoverage {
	c := AuditCoverage{}
	if scan != nil {
		c.FilesScanned = scan.FilesScanned
	}
	if check != nil && check.Coverage != nil {
		c.PackageEvidence = check.Coverage.PackageEvidence
		c.UnsupportedEvidence = check.Coverage.UnsupportedEvidence
		c.UnresolvedIncludes = check.Coverage.UnresolvedIncludes
	}
	return c
}

// noPackageFindingsLine is the package-check line for a result with no
// findings. The success mark is kept for checks that read evidence; a
// check that read nothing says so instead of reporting a clean result.
// A nil coverage (callers that did not compute it) keeps the old line.
func noPackageFindingsLine(st output.Style, c *packagecheck.Coverage) string {
	switch {
	case c != nil && c.Evaluated() && noExactVersions(c):
		// Read, but only advisories covering every version could be
		// matched: not a clean result.
		return st.SeverityIcon("MEDIUM") + " " + st.Yellow("No pinned versions were found, so no exact version was checked; only advisories covering every version were.")
	case c == nil || c.Evaluated():
		return st.OK("No known-compromised packages or persistence artifacts found.")
	case len(c.UnsupportedEvidence) > 0:
		unparsed, noIntel, manifests := splitUnsupported(c.UnsupportedEvidence)
		var msg string
		switch {
		case len(unparsed) == 0 && len(noIntel) == 0:
			msg = "No resolved versions were checked: the dependency manifests found have no lockfile, so an install would resolve versions nothing checked."
		case len(manifests) > 0:
			msg = "No resolved versions were checked: the dependency files found are manifests without a lockfile, formats Aguara cannot parse, or ecosystems it has no package intelligence for."
		case len(noIntel) == 0:
			msg = "No packages were checked: every dependency file found is in a format Aguara cannot parse."
		case len(unparsed) == 0:
			msg = "No packages were checked: Aguara has no package intelligence for the ecosystems of the dependency files found."
		default:
			msg = "No packages were checked: the dependency files found are in formats Aguara cannot parse or ecosystems it has no package intelligence for."
		}
		return st.SeverityIcon("MEDIUM") + " " + st.Yellow(msg)
	default:
		return st.Dim("No dependency files found; no packages were checked.")
	}
}

// noExactVersions reports evidence in which every package read is
// unpinned (and at least one package was read). Constraints files are
// not counted: they install nothing.
func noExactVersions(c *packagecheck.Coverage) bool {
	read := 0
	for _, e := range c.PackageEvidence {
		if packagecheck.IsConstraintsFile(e.Source) {
			continue
		}
		if e.Unpinned < e.PackagesRead {
			return false
		}
		read += e.PackagesRead
	}
	return read > 0
}

// splitUnsupported separates files Aguara cannot parse from files of
// ecosystems it has no package intelligence for and from manifests that
// have no evaluated lockfile. Requirements files read except for some
// lines count as files it cannot parse; partlyRead separates them.
func splitUnsupported(evidence []packagecheck.UnsupportedEvidence) (unparsed, noIntel, manifests []packagecheck.UnsupportedEvidence) {
	for _, u := range evidence {
		switch {
		case u.IsManifest():
			manifests = append(manifests, u)
		case u.NoIntel():
			noIntel = append(noIntel, u)
		default:
			unparsed = append(unparsed, u)
		}
	}
	return unparsed, noIntel, manifests
}

// partlyRead splits off the requirements files that were read except for
// the lines they list.
func partlyRead(evidence []packagecheck.UnsupportedEvidence) (partial, rest []packagecheck.UnsupportedEvidence) {
	for _, u := range evidence {
		if u.PartlyRead() {
			partial = append(partial, u)
		} else {
			rest = append(rest, u)
		}
	}
	return partial, rest
}

// pinsChecked sums the exact pins matched in evidence.
func pinsChecked(evidence []packagecheck.UnsupportedEvidence) int {
	n := 0
	for _, u := range evidence {
		n += u.ExactPinsChecked
	}
	return n
}

// pinsNote is the terminal suffix for exact pins checked in files that
// were otherwise not evaluated.
func pinsNote(evidence []packagecheck.UnsupportedEvidence) string {
	n := pinsChecked(evidence)
	if n == 0 {
		return ""
	}
	where := "in them"
	if len(evidence) == 1 {
		where = "in it"
	}
	return fmt.Sprintf("; %d exact %s %s %s checked", n, plural(n, "pin", "pins"), where, plural(n, "was", "were"))
}

// noIntelEcosystems lists the distinct ecosystems of evidence, in order.
func noIntelEcosystems(evidence []packagecheck.UnsupportedEvidence) string {
	var ecos []string
	for _, u := range evidence {
		if !slices.Contains(ecos, u.Ecosystem) {
			ecos = append(ecos, u.Ecosystem)
		}
	}
	return strings.Join(ecos, ", ")
}

// packageCoverageLine is the one-line terminal summary of the package
// evidence a check read.
func packageCoverageLine(c *packagecheck.Coverage) string {
	if c == nil {
		return ""
	}
	if !c.Evaluated() {
		return "Coverage: no supported dependency evidence was read"
	}
	parts := make([]string, 0, len(c.PackageEvidence))
	for _, e := range c.PackageEvidence {
		part := fmt.Sprintf("%s %s: %d packages", e.Ecosystem, e.Source, e.PackagesRead)
		if e.Targets > 1 {
			part += fmt.Sprintf(" from %d files", e.Targets)
		}
		if e.Unpinned > 0 {
			part += fmt.Sprintf(" (%d unpinned)", e.Unpinned)
		}
		parts = append(parts, output.TerminalText(part))
	}
	return "Coverage: " + strings.Join(parts, " · ")
}

// unsupportedEvidenceLines lists dependency files that were found but not
// evaluated, relative to root when possible: one line for formats Aguara
// cannot parse, one for ecosystems it has no package intelligence for,
// and one for manifests without a lockfile. Empty when there are none.
func unsupportedEvidenceLines(c *packagecheck.Coverage, root string) []string {
	if c == nil || len(c.UnsupportedEvidence) == 0 {
		return nil
	}
	unparsed, noIntel, manifests := splitUnsupported(c.UnsupportedEvidence)
	partial, unparsed := partlyRead(unparsed)
	var lines []string
	const maxPartial = 3
	for i, u := range partial {
		if i == maxPartial {
			lines = append(lines, fmt.Sprintf("Partly evaluated: %d more requirements files with lines Aguara cannot read (see coverage.unsupported_evidence)", len(partial)-maxPartial))
			break
		}
		lines = append(lines, fmt.Sprintf("Partly evaluated: %s (%s)",
			output.TerminalText(displayPath(root, u.Path)), output.TerminalText(u.Detail)))
	}
	if len(unparsed) > 0 {
		lines = append(lines, fmt.Sprintf("Not evaluated: %s (dependency %s Aguara cannot parse; no packages in %s were checked%s)",
			listedPaths(unparsed, root), plural(len(unparsed), "file", "files"), plural(len(unparsed), "it", "them"), pinsNote(unparsed)))
	}
	if len(noIntel) > 0 {
		lines = append(lines, fmt.Sprintf("Not evaluated: %s (Aguara has no package intelligence for %s; no packages in %s were checked%s)",
			listedPaths(noIntel, root), output.TerminalText(noIntelEcosystems(noIntel)), plural(len(noIntel), "it", "them"), pinsNote(noIntel)))
	}
	if len(manifests) > 0 {
		lines = append(lines, fmt.Sprintf("Not evaluated: %s (dependency %s without a lockfile; the versions an install would resolve were not checked%s)",
			listedPaths(manifests, root), plural(len(manifests), "manifest", "manifests"), pinsNote(manifests)))
	}
	return lines
}

// listedPaths names up to three files for a terminal line.
func listedPaths(evidence []packagecheck.UnsupportedEvidence, root string) string {
	const maxListed = 3
	names := make([]string, 0, maxListed+1)
	for i, u := range evidence {
		if i == maxListed {
			names = append(names, fmt.Sprintf("+%d more", len(evidence)-maxListed))
			break
		}
		names = append(names, output.TerminalText(displayPath(root, u.Path)))
	}
	return strings.Join(names, ", ")
}

// unsupportedEvidenceNames names unsupported files for triage messages,
// noting the files Aguara has no package intelligence for. Long lists
// are cut after a few names; the full list stays in
// coverage.unsupported_evidence.
func unsupportedEvidenceNames(evidence []packagecheck.UnsupportedEvidence, root string) string {
	const maxNamed = 5
	names := make([]string, 0, maxNamed+1)
	for i, u := range evidence {
		if i == maxNamed {
			names = append(names, fmt.Sprintf("and %d more listed in coverage.unsupported_evidence", len(evidence)-maxNamed))
			break
		}
		name := displayPath(root, u.Path)
		switch {
		case u.IsManifest() && u.NestedManifests > 0:
			name += fmt.Sprintf(" (%s workspace root, %d more %s below it%s)", u.Ecosystem, u.NestedManifests, plural(u.NestedManifests, "manifest", "manifests"), detailSuffix(u))
		case u.IsManifest():
			name += " (" + u.Ecosystem + detailSuffix(u) + ")"
		case u.NoIntel():
			name += " (Aguara has no package intelligence for " + u.Ecosystem + ")"
		case u.PartlyRead():
			name += " (" + u.Detail + ")"
		}
		names = append(names, name)
	}
	return strings.Join(names, ", ")
}

// detailSuffix is "; <detail>" for an entry that explains itself, such as
// a manifest whose requirements file does not pin its dependencies.
func detailSuffix(u packagecheck.UnsupportedEvidence) string {
	if u.Detail == "" {
		return ""
	}
	return "; " + u.Detail
}

// displayPath shortens path to be relative to root when it lies inside.
func displayPath(root, path string) string {
	if root == "" {
		root = "."
	}
	absRoot, err1 := filepath.Abs(root)
	absPath, err2 := filepath.Abs(path)
	if err1 != nil || err2 != nil {
		return path
	}
	rel, err := filepath.Rel(absRoot, absPath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return path
	}
	return filepath.ToSlash(rel)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
