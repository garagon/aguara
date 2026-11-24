package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/incident"
	"github.com/stretchr/testify/require"
)

// An include pip would read but Aguara does not, and requirements that
// name no single version, must be visible in every output, not only as
// JSON counters: otherwise a malicious pin in the skipped file reads as
// a clean pass.
func TestUnresolvedIncludesAndUnpinnedRequirementsAreVisible(t *testing.T) {
	isolatePythonCheck(t, "")
	base := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(base, "shared"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(base, "shared", "reqs.txt"), []byte("num2words==0.5.15\n"), 0o644))
	project := filepath.Join(base, "project")
	require.NoError(t, os.MkdirAll(project, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(project, "requirements.txt"), []byte(strings.Join([]string{
		"-r ../shared/reqs.txt",
		"requests>=2",
		"flask",
		"-r https://deploy:s3cretTOKEN@example.com/extra.txt",
		"-r missing.txt",
		"",
	}, "\n")), 0o644))

	checked := checkToFile(t, project)
	var warnings []incident.Finding
	for _, f := range checked.Findings {
		require.Equal(t, incident.SevWarning, f.Severity, f.Title)
		warnings = append(warnings, f)
	}
	require.Len(t, warnings, 3, "one warning per include that was not read")
	byLine := map[int]incident.Finding{}
	for _, w := range warnings {
		require.Equal(t, filepath.Join(project, "requirements.txt"), w.Path)
		byLine[w.Line] = w
		require.NotContains(t, w.Title+w.Detail+w.Remediation, "s3cretTOKEN", "URL credentials are redacted")
	}
	require.Contains(t, byLine[1].Title, "../shared/reqs.txt")
	require.Contains(t, byLine[1].Title, "outside the checked directory")
	require.Contains(t, byLine[4].Title, "https://redacted@example.com/extra.txt")
	require.Contains(t, byLine[4].Title, "URL")
	require.Contains(t, byLine[5].Title, "missing.txt")
	require.Contains(t, byLine[5].Title, "does not exist")
	require.NoError(t, checkIncidentFailOnThreshold(checked, "critical"), "check --ci fails only on critical findings")
	require.ErrorIs(t, checkIncidentFailOnThreshold(checked, "warning"), ErrThresholdExceeded)

	audited := auditToFile(t, project)
	require.Equal(t, "findings", audited.Verdict.Status, "not a clean pass")
	require.Equal(t, 3, audited.Verdict.CheckWarnings)
	require.False(t, audited.Verdict.ThresholdExceeded)
	require.Equal(t, "review", audited.Triage.Decision)
	require.False(t, audited.Plan.CanInstallDependencies)
	ci, err := computeAuditVerdict(audited, "critical")
	require.NoError(t, err)
	require.False(t, ci.ThresholdExceeded, "audit --ci does not fail on warnings")

	// Both terminal reports say how many requirements were not pinned.
	resetFlags()
	flagNoColor = true
	plan, err := buildCheckPlan(nil, project)
	require.NoError(t, err)
	fetch, restore := captureStdout(t)
	require.NoError(t, writeCheckTerminal(checked, plan))
	restore()
	out := fetch()
	require.Contains(t, out, "2 Python dependencies are not pinned to one version")
	require.Contains(t, out, "outside the checked directory")

	fetch, restore = captureStdout(t)
	require.NoError(t, writeAuditTerminal(audited))
	restore()
	out = fetch()
	require.Contains(t, out, "2 Python dependencies are not pinned to one version")
	require.Contains(t, out, "Verdict: FINDINGS")
	resetFlags()
}

func TestNoUnpinnedNoteWhenEverythingIsPinned(t *testing.T) {
	isolatePythonCheck(t, "")
	project := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(project, "requirements.txt"), []byte("six==1.16.0\n"), 0o644))
	checked := checkToFile(t, project)
	require.Empty(t, checked.Findings)
	resetFlags()
	flagNoColor = true
	plan, err := buildCheckPlan(nil, project)
	require.NoError(t, err)
	fetch, restore := captureStdout(t)
	require.NoError(t, writeCheckTerminal(checked, plan))
	restore()
	require.NotContains(t, fetch(), "not pinned")
	resetFlags()
}
