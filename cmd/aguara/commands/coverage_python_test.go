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
// of proceeding on a malicious pin it never checked.
func TestAuditReportsUnreadPythonRequirementsNames(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	for _, name := range []string{"dev-requirements.txt", "test_requirements.txt", "requirements/dev.txt"} {
		t.Run(name, func(t *testing.T) {
			dir := projectWith(t, map[string]string{name: "litellm==1.82.7\n"})
			result := auditToFile(t, dir)
			require.Equal(t, []string{name}, unsupportedRelPaths(t, dir, result))
			require.Equal(t, "review", result.Triage.Decision)
			requireTriageReason(t, result.Triage, "dependency_evidence_not_evaluated")
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

// The same file, not included, is unsupported even beside a read
// requirements.txt, so the partial-coverage rule applies.
func TestUnincludedRequirementsDirFileIsPartialCoverage(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := projectWith(t, map[string]string{
		"requirements.txt":     "flask==3.0.0\n",
		"requirements/dev.txt": "litellm==1.82.7\n",
	})
	result := auditToFile(t, dir)
	require.Equal(t, []string{"requirements/dev.txt"}, unsupportedRelPaths(t, dir, result))
	require.Equal(t, "review", result.Triage.Decision)
	requireTriageReason(t, result.Triage, "partial_dependency_coverage")
}
