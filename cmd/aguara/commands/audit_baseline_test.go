package commands

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// runAuditErr runs `aguara audit` in-process and returns the command
// error (ErrThresholdExceeded when the gate trips). JSON output goes to
// a temp file so it does not pollute the test log.
func runAuditErr(t *testing.T, args ...string) error {
	t.Helper()
	resetFlags()
	out := filepath.Join(t.TempDir(), "audit.json")
	full := append([]string{"audit"}, args...)
	full = append(full, "-o", out, "--format", "json", "--no-update-check")
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs(full)
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		resetFlags()
	})
	return rootCmd.Execute()
}

func writeCompromisedNPM(t *testing.T, dir string) {
	t.Helper()
	nm := filepath.Join(dir, "node_modules", "event-stream")
	require.NoError(t, os.MkdirAll(nm, 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(nm, "package.json"),
		[]byte(`{"name":"event-stream","version":"3.3.6"}`),
		0o644,
	))
}

// TestAuditBaselineSuppressesScanGate proves a baseline suppresses
// SCAN findings from the audit gate.
func TestAuditBaselineSuppressesScanGate(t *testing.T) {
	dir := t.TempDir()
	writeEvil(t, dir, "evil.md") // a HIGH, baselineable scan finding; no packages
	bl := filepath.Join(t.TempDir(), "baseline.json")

	// Sanity: without a baseline the scan HIGH finding trips --fail-on warning.
	require.ErrorIs(t, runAuditErr(t, dir, "--fail-on", "warning"), ErrThresholdExceeded)

	// Establish the baseline (audit --write-baseline, scan half).
	require.NoError(t, runAuditErr(t, dir, "--write-baseline", bl))
	require.FileExists(t, bl)

	// With the baseline applied, the same scan finding no longer gates.
	result := auditToFile(t, dir, "--baseline", bl, "--fail-on", "warning")
	require.NotNil(t, result.Scan.Baseline)
	require.Equal(t, 0, result.Scan.Baseline.New, "pre-existing scan finding must be baselined, not new")
	require.GreaterOrEqual(t, result.Scan.Baseline.Baselined, 1)
	require.False(t, result.Verdict.ThresholdExceeded, "baselined scan finding must not trip the gate")
}

// TestAuditBaselineDoesNotSuppressPackageFindings proves the baseline
// never silences package / check findings: a compromised dependency
// still gates whether the baseline is being consumed or written.
func TestAuditBaselineDoesNotSuppressPackageFindings(t *testing.T) {
	dir := t.TempDir()
	writeEvil(t, dir, "evil.md") // baselineable scan finding
	writeCompromisedNPM(t, dir)  // event-stream@3.3.6 -> critical check finding
	bl := filepath.Join(t.TempDir(), "baseline.json")

	// Writing a scan baseline accepts the scan side, but the compromised
	// package must still gate.
	err := runAuditErr(t, dir, "--write-baseline", bl, "--fail-on", "critical")
	require.ErrorIs(t, err, ErrThresholdExceeded, "package finding must gate even during --write-baseline")
	require.FileExists(t, bl)

	// Consuming the baseline suppresses the scan finding but the
	// compromised package still trips the critical gate.
	err = runAuditErr(t, dir, "--baseline", bl, "--fail-on", "critical")
	require.ErrorIs(t, err, ErrThresholdExceeded, "baseline must not suppress package/check findings")

	// And the check finding is still present in the emitted result.
	result := auditToFile(t, dir, "--baseline", bl)
	require.NotEmpty(t, result.Check.Findings, "compromised package must remain in the check sub-result")
	require.Greater(t, result.Verdict.CheckCriticals, 0)
}

// TestAuditBaselineFlagsMutuallyExclusive guards the flag contract.
func TestAuditBaselineFlagsMutuallyExclusive(t *testing.T) {
	dir := t.TempDir()
	writeEvil(t, dir, "evil.md")
	err := runAuditErr(t, dir, "--baseline", "a.json", "--write-baseline", "b.json")
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrThresholdExceeded)
}
