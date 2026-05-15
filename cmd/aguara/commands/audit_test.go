package commands

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/garagon/aguara/internal/incident"
	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
	"github.com/stretchr/testify/require"
)

// auditToFile runs `aguara audit` with the given args, writes JSON
// output to a temp file via `-o`, and returns the parsed result.
// Same pattern as scanToFile / checkToFile.
func auditToFile(t *testing.T, args ...string) *AuditResult {
	t.Helper()
	resetFlags()
	outFile := filepath.Join(t.TempDir(), "audit.json")
	fullArgs := append([]string{"audit"}, args...)
	fullArgs = append(fullArgs, "-o", outFile, "--format", "json", "--no-update-check")

	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs(fullArgs)
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		resetFlags()
	})

	err := rootCmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	var result AuditResult
	require.NoError(t, json.Unmarshal(data, &result))
	return &result
}

func TestAuditCleanProject(t *testing.T) {
	// An empty project audit must succeed cleanly: check passes
	// (no compromised packages), scan passes (no findings), and
	// the verdict is "pass" with zero counts.
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "README.md"), []byte("# clean"), 0o644))

	result := auditToFile(t, dir)
	require.NotNil(t, result.Check)
	require.NotNil(t, result.Scan)
	require.Equal(t, "pass", result.Verdict.Status)
	require.False(t, result.Verdict.ThresholdExceeded)
	require.Empty(t, result.Check.Findings)
}

func TestAuditDetectsCompromisedNPMPackage(t *testing.T) {
	// Audit on a project with a known-compromised npm package
	// surfaces it in the Check sub-result and the verdict
	// reflects the critical count. The supply-chain side carries
	// IntelSummary so the JSON consumer sees provenance.
	dir := t.TempDir()
	nm := filepath.Join(dir, "node_modules")
	require.NoError(t, os.MkdirAll(filepath.Join(nm, "event-stream"), 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(nm, "event-stream", "package.json"),
		[]byte(`{"name":"event-stream","version":"3.3.6"}`),
		0o644,
	))

	result := auditToFile(t, dir)
	require.NotEmpty(t, result.Check.Findings, "compromised event-stream@3.3.6 must surface in audit")
	require.Greater(t, result.Verdict.CheckCriticals, 0)
}

func TestAuditCIFailsOnCritical(t *testing.T) {
	// audit --ci with a compromised package must exit non-zero
	// so a release pipeline gates on it. Subprocess pattern:
	// ErrThresholdExceeded is the sentinel main.go maps to
	// os.Exit(1).
	dir := t.TempDir()
	nm := filepath.Join(dir, "node_modules")
	require.NoError(t, os.MkdirAll(filepath.Join(nm, "event-stream"), 0o755))
	require.NoError(t, os.WriteFile(
		filepath.Join(nm, "event-stream", "package.json"),
		[]byte(`{"name":"event-stream","version":"3.3.6"}`),
		0o644,
	))

	cmd := exec.Command("go", "test", "-race", "-count=1",
		"-run", "TestAuditCIFailsOnCriticalHelper",
		"./cmd/aguara/commands/",
	)
	cmd.Dir = filepath.Join("..", "..", "..")
	cmd.Env = append(os.Environ(), "AGUARA_TEST_AUDIT_CI_DIR="+dir)

	out, err := cmd.CombinedOutput()
	require.Error(t, err, "expected non-zero exit: %s", string(out))
}

// TestAuditCIFailsOnCriticalHelper is invoked by TestAuditCIFailsOnCritical
// in a subprocess; skipped when not.
func TestAuditCIFailsOnCriticalHelper(t *testing.T) {
	dir := os.Getenv("AGUARA_TEST_AUDIT_CI_DIR")
	if dir == "" {
		t.Skip("only runs as subprocess of TestAuditCIFailsOnCritical")
	}
	resetFlags()
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{
		"audit", dir,
		"--ci",
		"--format", "json",
		"-o", filepath.Join(t.TempDir(), "out.json"),
		"--no-update-check",
	})
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		resetFlags()
	})

	if err := rootCmd.Execute(); errors.Is(err, ErrThresholdExceeded) {
		os.Exit(1)
	}
}

func TestAuditVerdictWarningTrips(t *testing.T) {
	// computeAuditVerdict's warning threshold must trip on
	// either a check warning OR a scan high. Direct unit test
	// because building a fixture that emits a scan-high finding
	// from the audit pipeline is expensive.
	result := &AuditResult{
		Check: nil,
		Scan:  nil,
	}
	// Use the public-but-internal helper via reflection of the
	// computed fields. Simpler: stub the result + call the
	// helper directly.
	v := computeAuditVerdict(stubAuditResult(t, 0, 1, 0, 0), "warning")
	require.True(t, v.ThresholdExceeded)
	require.Equal(t, "fail", v.Status)
	require.Equal(t, 1, v.CheckWarnings)

	v = computeAuditVerdict(stubAuditResult(t, 0, 0, 0, 1), "warning")
	require.True(t, v.ThresholdExceeded, "scan high must trip warning threshold")
	_ = result
}

func TestAuditVerdictCriticalPassesOnWarningOnly(t *testing.T) {
	v := computeAuditVerdict(stubAuditResult(t, 0, 1, 0, 0), "critical")
	require.False(t, v.ThresholdExceeded, "single warning must not trip critical gate")
	require.Equal(t, "pass", v.Status)
}

// stubAuditResult builds a minimal AuditResult with the requested
// finding counts. checkC/W are check criticals/warnings;
// scanC/H are scan criticals/highs. Used in the verdict unit
// tests.
func stubAuditResult(t *testing.T, checkC, checkW, scanC, scanH int) *AuditResult {
	t.Helper()
	check := &incident.CheckResult{}
	for i := 0; i < checkC; i++ {
		check.Findings = append(check.Findings, incident.Finding{Severity: incident.SevCritical})
	}
	for i := 0; i < checkW; i++ {
		check.Findings = append(check.Findings, incident.Finding{Severity: incident.SevWarning})
	}
	scan := &scanner.ScanResult{}
	for i := 0; i < scanC; i++ {
		scan.Findings = append(scan.Findings, types.Finding{Severity: scanner.SeverityCritical})
	}
	for i := 0; i < scanH; i++ {
		scan.Findings = append(scan.Findings, types.Finding{Severity: scanner.SeverityHigh})
	}
	return &AuditResult{Check: check, Scan: scan}
}
