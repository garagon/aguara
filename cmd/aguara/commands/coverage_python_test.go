package commands

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func unsupportedRelPaths(t *testing.T, dir string, result *AuditResult) []string {
	t.Helper()
	var out []string
	for _, u := range result.Coverage.UnsupportedEvidence {
		rel, err := filepath.Rel(dir, u.Path)
		require.NoError(t, err)
		out = append(out, filepath.ToSlash(rel))
	}
	return out
}

// A pip requirements file under a name discovery does not read is
// reported as unsupported evidence, so the audit asks for review instead
// of proceeding on versions it never checked as a project's own.
func TestAuditReportsUnreadPythonRequirementsNames(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	for _, name := range []string{"dev-requirements.txt", "test_requirements.txt", "requirements/dev.txt",
		"dev-reqs.txt", "reqs.txt", "test_reqs.txt", "requirements.pip", "requirements/base.pip"} {
		t.Run(name, func(t *testing.T) {
			dir := projectWith(t, map[string]string{name: "flask==3.0.0\npytest>=7\n"})
			result := auditToFile(t, dir)
			require.Equal(t, []string{name}, unsupportedRelPaths(t, dir, result))
			require.Equal(t, "requirements_name_not_read", result.Coverage.UnsupportedEvidence[0].Reason)
			require.Equal(t, 1, result.Coverage.UnsupportedEvidence[0].ExactPinsChecked)
			require.Equal(t, "review", result.Triage.Decision)
			requireTriageReason(t, result.Triage, "dependency_evidence_not_evaluated")
			require.False(t, result.Plan.CanInstallDependencies)
			require.Equal(t, "pass", result.Verdict.Status)
		})
	}
}

// An exact pin in such a file is matched against intelligence: a
// compromised release it pins is a finding, not only a review.
func TestAuditMatchesPinsInUnreadPythonRequirementsNames(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	for _, name := range []string{"dev-requirements.txt", "dev-reqs.txt", "requirements.pip"} {
		t.Run(name, func(t *testing.T) {
			dir := projectWith(t, map[string]string{name: "litellm==1.82.7\n"})
			result := auditToFile(t, dir)
			require.Equal(t, []string{name}, unsupportedRelPaths(t, dir, result))
			require.Equal(t, "stop", result.Triage.Decision)
			require.Equal(t, 1, result.Verdict.CheckCriticals)
			require.Len(t, result.Check.Findings, 1)
			require.Equal(t, filepath.Join(dir, filepath.FromSlash(name)), result.Check.Findings[0].Path)
			require.Equal(t, 1, result.Check.Findings[0].Line)
			requireTriageReason(t, result.Triage, "dependency_evidence_not_evaluated")
			require.False(t, result.Plan.CanInstallDependencies)
		})
	}
}

// The file name must not decide the outcome: the same range-only content
// reviews whether discovery reads the file by name (requirements-dev.txt,
// unpinned entries) or not (dev-requirements.txt, unsupported evidence).
func TestRangeOnlyPipFileReviewsWhateverItsName(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	for name, reason := range map[string]string{
		"requirements-dev.txt": "unpinned_dependency_evidence",
		"dev-requirements.txt": "dependency_evidence_not_evaluated",
	} {
		t.Run(name, func(t *testing.T) {
			result := auditToFile(t, projectWith(t, map[string]string{name: "pytest>=7\n"}))
			require.Equal(t, "review", result.Triage.Decision)
			requireTriageReason(t, result.Triage, reason)
			require.False(t, result.Plan.CanInstallDependencies)
		})
	}
}

// A requirements file that is read through an include from a discovered
// requirements.txt was evaluated: it is not unsupported evidence, and a
// malicious pin in it is a finding.
func TestIncludedRequirementsFileIsNotUnsupported(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := projectWith(t, map[string]string{
		"requirements.txt":     "-r requirements/dev.txt\nflask==3.0.0\n",
		"requirements/dev.txt": "litellm==1.82.7\n",
	})
	result := auditToFile(t, dir)
	require.Empty(t, result.Coverage.UnsupportedEvidence)
	require.Equal(t, "stop", result.Triage.Decision)
	require.Equal(t, 1, result.Verdict.CheckCriticals)
	var paths []string
	for _, f := range result.Check.Findings {
		paths = append(paths, f.Path)
	}
	require.Contains(t, strings.Join(paths, "\n"), filepath.Join("requirements", "dev.txt"))
}

// A documentation file named constraints.txt is not pip syntax: check
// names it as not evaluated and succeeds, and audit asks for review,
// instead of the whole run failing.
func TestNonPipFileUnderARequirementsNameIsNotEvaluated(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := projectWith(t, map[string]string{
		"docs/constraints.txt": "Constraints\n===========\n\n.. class:: CheckConstraint(*, check, name)\n",
		"requirements.txt":     "flask==3.0.0\n",
	})
	check := checkToFile(t, dir)
	require.Len(t, check.Coverage.UnsupportedEvidence, 1)
	u := check.Coverage.UnsupportedEvidence[0]
	require.Equal(t, filepath.Join(dir, "docs", "constraints.txt"), u.Path)
	require.Equal(t, "constraints.txt", u.Kind)
	require.Equal(t, "format_not_parsed", u.Reason)
	require.Contains(t, u.Detail, "line 2")

	result := auditToFile(t, dir)
	require.Equal(t, "review", result.Triage.Decision)
	requireTriageReason(t, result.Triage, "partial_dependency_coverage")
	require.False(t, result.Plan.CanInstallDependencies)
}

// The same file, not included, is unsupported even beside a read
// requirements.txt, so the partial-coverage rule applies.
func TestUnincludedRequirementsDirFileIsPartialCoverage(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := projectWith(t, map[string]string{
		"requirements.txt":     "flask==3.0.0\n",
		"requirements/dev.txt": "pytest==8.2.0\n",
	})
	result := auditToFile(t, dir)
	require.Equal(t, []string{"requirements/dev.txt"}, unsupportedRelPaths(t, dir, result))
	require.Equal(t, "review", result.Triage.Decision)
	requireTriageReason(t, result.Triage, "partial_dependency_coverage")
}
