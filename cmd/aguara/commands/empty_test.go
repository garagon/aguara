package commands

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func readReport(t *testing.T, args ...string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "report")
	require.NoError(t, runCLI(t, append(args, "-o", out)...))
	data, err := os.ReadFile(out)
	require.NoError(t, err)
	return string(data)
}

// A scan of zero files says nothing was scanned instead of showing a
// success mark with "No security issues found".
func TestEmptyScanIsNotReportedAsClean(t *testing.T) {
	empty := t.TempDir()

	out := readReport(t, "scan", empty)
	require.Contains(t, out, "Nothing was scanned: no scannable files under the target")
	require.NotContains(t, out, "No security issues found")
	require.NotContains(t, out, "✔")

	out = readReport(t, "scan", empty, "--format", "markdown")
	require.Contains(t, out, "**Nothing scanned**")
	require.NotContains(t, out, "Passed")
	require.NotContains(t, out, "No security issues found")

	repo := commitRepo(t, map[string]string{"a.md": "# a\n"})
	out = readReport(t, "scan", repo, "--changed")
	require.Contains(t, out, "Nothing was scanned: no changed files under the target")
}

// Zero files scanned keeps the default exit code; only the report and
// the audit decision change.
func TestEmptyScanKeepsDefaultExitCode(t *testing.T) {
	require.NoError(t, runCLI(t, "scan", t.TempDir(), "--fail-on", "low", "-o", filepath.Join(t.TempDir(), "r")))
}

// An audit that scanned nothing cannot clear the target: triage asks for
// review, and handoff and action plan withhold install and execution.
func TestEmptyAuditDoesNotProceed(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	empty := t.TempDir()

	result := auditToFile(t, empty)
	require.Equal(t, "pass", result.Verdict.Status, "verdict.status keeps its findings-based meaning")
	require.Equal(t, 0, result.Coverage.FilesScanned)
	require.Equal(t, "review", result.Triage.Decision)
	requireTriageReason(t, result.Triage, "nothing_scanned")
	require.Equal(t, "review_only", result.Handoff.Status)
	require.Equal(t, "review_only", result.Plan.TrustState)
	require.False(t, result.Plan.CanInstallDependencies)
	require.False(t, result.Plan.CanExecuteProjectCode)
	require.False(t, result.Plan.CanRunCI)
	require.Contains(t, result.Plan.Priority, "nothing_scanned")

	out := readReport(t, "audit", empty)
	require.Contains(t, out, "Nothing was scanned")
	require.Contains(t, out, "No dependency files found; no packages were checked.")
	require.Contains(t, out, "Triage: REVIEW")
	require.Contains(t, out, "install=no")
	require.NotContains(t, out, "✔")
}

// A check that read no dependency evidence says so instead of a success
// mark. A project with no dependency files keeps exit code 0.
func TestCheckWithNoEvidenceSaysNothingWasChecked(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	out := readReport(t, "check", t.TempDir())
	require.Contains(t, out, "Coverage: no supported dependency evidence was read")
	require.Contains(t, out, "No dependency files found; no packages were checked.")
	require.NotContains(t, out, "✔")
}
