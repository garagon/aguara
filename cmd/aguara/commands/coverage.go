package commands

import (
	"encoding/json"
	"fmt"
	"path/filepath"
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
}

// MarshalJSON keeps both arrays as `[]` rather than `null` when empty.
func (c AuditCoverage) MarshalJSON() ([]byte, error) {
	if c.PackageEvidence == nil {
		c.PackageEvidence = []packagecheck.EvidenceSummary{}
	}
	if c.UnsupportedEvidence == nil {
		c.UnsupportedEvidence = []packagecheck.UnsupportedEvidence{}
	}
	type alias AuditCoverage
	return json.Marshal(alias(c))
}

// checkCoverage builds the coverage block for a finished check. A file
// that discovery also returned as a parsed target is never reported as
// unsupported, so adding a parser cannot produce a contradictory entry.
func checkCoverage(plan checkPlan, result *incident.CheckResult) *packagecheck.Coverage {
	read := map[string]bool{}
	for _, e := range result.Ecosystems {
		read[filepath.Clean(e.Path)] = true
	}
	unsupported := []packagecheck.UnsupportedEvidence{}
	for _, u := range plan.unsupported {
		if !read[filepath.Clean(u.Path)] {
			unsupported = append(unsupported, u)
		}
	}
	return &packagecheck.Coverage{
		PackageEvidence:     packagecheck.SummarizeEvidence(result.Ecosystems),
		UnsupportedEvidence: unsupported,
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
	}
	return c
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
		parts = append(parts, output.TerminalText(part))
	}
	return "Coverage: " + strings.Join(parts, " · ")
}

// unsupportedEvidenceLine lists dependency files that were found but not
// evaluated, relative to root when possible. Empty when there are none.
func unsupportedEvidenceLine(c *packagecheck.Coverage, root string) string {
	if c == nil || len(c.UnsupportedEvidence) == 0 {
		return ""
	}
	const maxListed = 3
	names := make([]string, 0, maxListed)
	for i, u := range c.UnsupportedEvidence {
		if i == maxListed {
			names = append(names, fmt.Sprintf("+%d more", len(c.UnsupportedEvidence)-maxListed))
			break
		}
		names = append(names, output.TerminalText(displayPath(root, u.Path)))
	}
	return fmt.Sprintf("Not evaluated: %s (dependency %s Aguara cannot parse; no packages in %s were checked)",
		strings.Join(names, ", "), plural(len(c.UnsupportedEvidence), "file", "files"),
		plural(len(c.UnsupportedEvidence), "it", "them"))
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
