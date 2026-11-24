package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const uvLockFixture = "@../../../internal/packagecheck/testdata/python-uv/uv.lock"

// A requirements file whose entries are all unpinned was read, but only
// advisories covering every version could be matched for it: the audit
// asks for review instead of clearing installation.
func TestAuditReviewsDependencyFilesWithNoPinnedEntry(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := projectWith(t, map[string]string{"requirements.txt": "requests>=2\nflask\n"})

	result := auditToFile(t, dir)
	require.Equal(t, "pass", result.Verdict.Status)
	require.Equal(t, "review", result.Triage.Decision)
	require.Equal(t, "Some dependency files pin no exact versions, so the audit cannot clear dependency installation.", result.Triage.Summary)
	requireTriageReason(t, result.Triage, "unpinned_dependency_evidence")
	for _, r := range result.Triage.Reasons {
		if r.Kind == "unpinned_dependency_evidence" {
			require.Equal(t, "warning", r.Severity)
			require.Contains(t, r.Message, "requirements.txt")
		}
	}
	require.False(t, result.Plan.CanInstallDependencies)
	require.Equal(t, 2, result.Coverage.PackageEvidence[0].Unpinned)

	out := readReport(t, "audit", dir)
	require.Contains(t, out, "(coverage incomplete, see triage)")
	require.Contains(t, out, "2 Python dependencies are not pinned to one version")
	require.Contains(t, out, "No pinned versions were found, so no exact version was checked")
	require.NotContains(t, out, "✔ No known-compromised packages")
	require.NotContains(t, out, "\x1b[")

	out = readReport(t, "check", dir)
	require.Contains(t, out, "Coverage: PyPI requirements.txt: 2 packages (2 unpinned)")
	require.Contains(t, out, "No pinned versions were found")
}

// One pinned entry is enough to count the file as evaluated; the
// unpinned entries are still reported by the terminal note and the JSON
// counts.
func TestAuditProceedsWhenSomeEntriesArePinned(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := projectWith(t, map[string]string{"requirements.txt": "requests>=2\nflask==3.0.0\n"})
	result := auditToFile(t, dir)
	require.Equal(t, "proceed", result.Triage.Decision)
	require.Equal(t, 1, result.Coverage.PackageEvidence[0].Unpinned)
	require.Contains(t, readReport(t, "audit", dir), "1 Python dependency is not pinned to one version")
}

// A Python lockfile that was evaluated clean does not cover an
// unsupported dependency file elsewhere in the project.
func TestAuditReviewsCleanUVLockBesideUnsupportedFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := projectWith(t, map[string]string{
		"uv.lock":       uvLockFixture,
		"web/deno.lock": denoLockFixture,
	})
	result := auditToFile(t, dir)
	require.Empty(t, result.Check.Findings)
	require.Equal(t, "review", result.Triage.Decision)
	requireTriageReason(t, result.Triage, "partial_dependency_coverage")
	require.False(t, result.Plan.CanInstallDependencies)
	require.Len(t, result.Coverage.PackageEvidence, 1)
	require.Equal(t, "uv.lock", result.Coverage.PackageEvidence[0].Source)
}

// -o and --format apply to the Python findings and terminal lines: the
// file gets the report in the selected format, without color codes, and
// stdout stays empty.
func TestPythonReportsHonorOutputAndFormat(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := projectWith(t, map[string]string{
		"uv.lock":          uvLockWithKnownMaliciousVersion,
		"requirements.txt": "-r missing.txt\nrequests>=2\n",
	})
	for _, command := range []string{"check", "audit"} {
		t.Run(command, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "report.txt")
			var err error
			stdout := captureStdoutBytes(t, func() { err = runCLI(t, command, dir, "-o", out) })
			require.NoError(t, err)
			require.Empty(t, string(stdout))
			data, readErr := os.ReadFile(out)
			require.NoError(t, readErr)
			text := string(data)
			require.NotContains(t, text, "\x1b[")
			require.Contains(t, text, "litellm 1.82.7 is a known compromised PyPI package")
			require.Contains(t, text, filepath.Join(dir, "uv.lock")+":", "findings carry their file:line location")
			require.Contains(t, text, "requirements.txt includes missing.txt, which was not checked")
			require.Contains(t, text, "1 Python dependency is not pinned to one version")

			jsonOut := filepath.Join(t.TempDir(), "report.json")
			require.NoError(t, runCLI(t, command, dir, "--format", "json", "-o", jsonOut))
			raw, readErr := os.ReadFile(jsonOut)
			require.NoError(t, readErr)
			var decoded map[string]any
			require.NoError(t, json.Unmarshal(raw, &decoded))
			require.Contains(t, string(raw), `"advisory_ids"`)
			require.Contains(t, string(raw), `"unresolved_includes"`)
		})
	}
}
