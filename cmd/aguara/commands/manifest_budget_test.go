package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/garagon/aguara/internal/incident"
	"github.com/garagon/aguara/internal/types"
)

// A dependency manifest over a parsing budget was listed like any manifest
// without a lockfile, and check and audit completed and exited 0 as if it
// had been evaluated. Its dependencies are unknown: the run is now
// incomplete (exit 2) and says which file, and every other result, here a
// package-lock.json that was checked and the manifest's own listing, stays
// in the report.
func TestManifestOverBudgetMakesCheckIncomplete(t *testing.T) {
	wide := `{"require":{"vendor/a":"1.0.0"},"x":[` + strings.Repeat("0,", 100_000) + `0]}`
	dir := projectWith(t, map[string]string{"package-lock.json": packageLockFixture, "composer.json": wide})
	readJSON := func(path string, v any) {
		t.Helper()
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(data, v), "%s", data)
	}
	requireIncompleteCheck := func(t *testing.T, c *incident.CheckResult) {
		t.Helper()
		require.True(t, c.Incomplete)
		require.Equal(t, 1, c.FailedOperations)
		require.Len(t, c.Errors, 1)
		require.Equal(t, "composer.json", filepath.Base(c.Errors[0].Path))
		require.Equal(t, types.FailureStageRead, c.Errors[0].Stage)
		require.Equal(t, types.FailureReasonBudget, c.Errors[0].Reason)
		require.NotNil(t, c.Coverage)
		var evidence, listed []string
		for _, e := range c.Coverage.PackageEvidence {
			evidence = append(evidence, e.Ecosystem)
		}
		for _, u := range c.Coverage.UnsupportedEvidence {
			listed = append(listed, u.Kind+" "+u.Reason)
		}
		require.Contains(t, evidence, "npm", "the package-lock.json evidence is kept")
		require.Contains(t, listed, "composer.json manifest_without_lockfile", "the manifest is still listed")
	}

	out := filepath.Join(t.TempDir(), "check.json")
	err := runCLI(t, "check", dir, "--format", "json", "-o", out)
	require.ErrorIs(t, err, errCheckIncomplete)
	var check incident.CheckResult
	readJSON(out, &check)
	requireIncompleteCheck(t, &check)

	text := filepath.Join(t.TempDir(), "check.txt")
	require.ErrorIs(t, runCLI(t, "check", dir, "--no-color", "-o", text), errCheckIncomplete)
	data, err := os.ReadFile(text)
	require.NoError(t, err)
	require.Contains(t, string(data), "CHECK INCOMPLETE: 1 dependency file(s) exceed a parsing budget")
	require.Contains(t, string(data), "composer.json: exceeds a parsing budget")

	out = filepath.Join(t.TempDir(), "audit.json")
	err = runCLI(t, "audit", dir, "--format", "json", "-o", out)
	require.ErrorIs(t, err, errCheckIncomplete)
	var audit AuditResult
	readJSON(out, &audit)
	require.False(t, audit.Complete)
	require.Equal(t, "incomplete", audit.Verdict.Status)
	require.Equal(t, "review", audit.Triage.Decision)
	require.True(t, hasTriageReason(audit.Triage.Reasons, "check_incomplete"))
	require.True(t, hasTriageReason(audit.Triage.Reasons, "manifest_without_lockfile"))
	require.False(t, audit.Plan.CanExecuteProjectCode)
	requireIncompleteCheck(t, audit.Check)

	// Without the over-budget file the same project is complete.
	require.NoError(t, os.Remove(filepath.Join(dir, "composer.json")))
	out = filepath.Join(t.TempDir(), "complete.json")
	require.NoError(t, runCLI(t, "check", dir, "--format", "json", "-o", out))
	raw, err := os.ReadFile(out)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"complete": true`)
	require.Contains(t, string(raw), `"errors": []`)
	require.Contains(t, string(raw), `"failed_operations": 0`)
}
