package incident

import (
	"fmt"
	"os"
	"strings"

	"github.com/garagon/aguara/internal/intel"
	"github.com/garagon/aguara/internal/packagecheck"
)

// maxEnvironmentDistributions bounds the dist-info directories one
// environment check reads. Real environments hold a few thousand.
const maxEnvironmentDistributions = 100_000

// CheckEnvironment evaluates one Python environment's site-packages
// directory (opts.Path, required): installed distributions are matched
// against the intel snapshot with the same name and version rules Check
// uses.
//
// It is the package evidence a project's virtual environment adds to a
// check of that project, so it reads nothing else. Host state
// (persistence artifacts, credential files, pip/uv caches) is not
// consulted, and .pth files are not inspected: that heuristic flags
// legitimate startup hooks (coverage.py's a1_coverage.pth, setuptools
// namespace and editable-finder files) and stays part of the
// installed-environment check, Check, where it has always run.
//
// Reads are bounded and never block on special files; an environment
// with more than maxEnvironmentDistributions distributions, or an
// unreadable directory, is an error rather than a partial clean result.
func CheckEnvironment(opts CheckOptions) (*CheckResult, error) {
	siteDir := opts.Path
	if siteDir == "" {
		return nil, fmt.Errorf("check: environment check needs a site-packages path")
	}
	if _, err := os.ReadDir(siteDir); err != nil {
		return nil, fmt.Errorf("check: cannot read site-packages directory %s: %w", siteDir, err)
	}
	packages, err := readInstalledPackagesLimit(siteDir, maxEnvironmentDistributions)
	if err != nil {
		return nil, fmt.Errorf("check: %w", err)
	}
	result := &CheckResult{
		Environment:  siteDir,
		Findings:     []Finding{},
		Credentials:  []CredentialFile{},
		Ecosystems:   []packagecheck.EcosystemResult{},
		Intel:        intelSummaryFor(opts),
		PackagesRead: len(packages),
	}
	matcher := matcherFor(opts)
	pypiFindings := 0
	for _, pkg := range packages {
		hits := matcher.MatchPackage(intel.MatchInput{
			Ecosystem: intel.EcosystemPyPI,
			Name:      pkg.Name,
			Version:   pkg.Version,
			Path:      pkg.Dir,
		})
		if len(hits) == 0 {
			continue
		}
		result.Findings = append(result.Findings, Finding{
			Severity:    SevCritical,
			Kind:        KindCompromisedPackage,
			Title:       fmt.Sprintf("%s %s is a known compromised package (%s)", pkg.Name, pkg.Version, strings.Join(matchIDs(hits), ", ")),
			Detail:      hits[0].Record.Summary,
			Path:        pkg.Dir,
			Remediation: fmt.Sprintf("Delete and recreate this virtual environment from a lockfile that does not pin %s %s, and rotate credentials that processes using it could reach.", pkg.Name, pkg.Version),
			AdvisoryIDs: matchIDs(hits),
			Ecosystem:   intel.EcosystemPyPI,
			Package:     pkg.Name,
			Version:     pkg.Version,
		})
		pypiFindings++
	}
	result.Ecosystems = append(result.Ecosystems, packagecheck.EcosystemResult{
		Ecosystem:     intel.EcosystemPyPI,
		Path:          siteDir,
		Source:        "site-packages",
		PackagesRead:  len(packages),
		FindingsCount: pypiFindings,
	})
	return result, nil
}

// matchIDs returns the distinct advisory IDs of a match set in order.
func matchIDs(matches []intel.Match) []string {
	ids := make([]string, 0, len(matches))
	seen := make(map[string]bool, len(matches))
	for _, m := range matches {
		if m.Record.ID != "" && !seen[m.Record.ID] {
			seen[m.Record.ID] = true
			ids = append(ids, m.Record.ID)
		}
	}
	return ids
}
