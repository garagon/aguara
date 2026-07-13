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
	require.Equal(t, "proceed", result.Triage.Decision)
	require.Empty(t, result.Check.Findings)
}

func TestAuditDetectsCompromisedNPMPackage(t *testing.T) {
	// Audit on a project with a known-compromised npm package
	// surfaces it in the Check sub-result and the verdict
	// reflects the critical count. The supply-chain side carries
	// IntelSummary so the JSON consumer sees provenance.
	//
	// Per #110 tri-state, the default audit (no --ci, no
	// --fail-on) must report Status="findings" when criticals
	// exist, not "pass". This is the canonical regression guard
	// for the v0.17.x bug where dashboards reading verdict.status
	// saw green while check_criticals > 0.
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
	require.Equal(t, "findings", result.Verdict.Status,
		"default audit (no gate) with criticals present must report tri-state 'findings', not 'pass'")
	require.False(t, result.Verdict.ThresholdExceeded,
		"no --ci / --fail-on means no gate; ThresholdExceeded must stay false")
	require.Equal(t, "stop", result.Triage.Decision,
		"triage answers whether to trust this repo now, independently from default audit exit policy")
	requireTriageReason(t, result.Triage, "known_malicious_package")
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

// TestAuditVerdictTriStateTable locks the 3x3 truth table for the
// tri-state verdict introduced in #110. The previous semantics
// collapsed "no findings" and "findings without a gate" into the
// same "pass" output, which masked critical findings from any
// dashboard that read verdict.status as the primary signal.
func TestAuditVerdictTriStateTable(t *testing.T) {
	cases := []struct {
		name            string
		check           *AuditResult
		threshold       string
		wantStatus      string
		wantThresholdEx bool
	}{
		{
			name:       "no findings, no threshold -> pass",
			check:      stubAuditResult(t, 0, 0, 0, 0, 0, 0),
			threshold:  "",
			wantStatus: "pass",
		},
		{
			name:       "no findings, --fail-on critical -> pass",
			check:      stubAuditResult(t, 0, 0, 0, 0, 0, 0),
			threshold:  "critical",
			wantStatus: "pass",
		},
		{
			name:       "criticals present, no threshold -> findings (the #110 bug case)",
			check:      stubAuditResult(t, 2, 0, 0, 0, 0, 0),
			threshold:  "",
			wantStatus: "findings",
		},
		{
			name:       "warnings only, no threshold -> findings",
			check:      stubAuditResult(t, 0, 1, 0, 0, 0, 0),
			threshold:  "",
			wantStatus: "findings",
		},
		{
			name:       "info only, no threshold -> findings (info still counts as visible findings)",
			check:      stubAuditResult(t, 0, 0, 0, 0, 1, 0),
			threshold:  "",
			wantStatus: "findings",
		},
		{
			name:            "criticals + --fail-on critical -> fail (gate crossed)",
			check:           stubAuditResult(t, 2, 0, 0, 0, 0, 0),
			threshold:       "critical",
			wantStatus:      "fail",
			wantThresholdEx: true,
		},
		{
			name:       "warnings + --fail-on critical -> findings (below the gate, exit 0)",
			check:      stubAuditResult(t, 0, 3, 0, 0, 0, 0),
			threshold:  "critical",
			wantStatus: "findings",
		},
		{
			name:       "scan lows only + --fail-on critical -> findings (below the gate)",
			check:      stubAuditResult(t, 0, 0, 0, 0, 0, 0), // build base
			threshold:  "critical",
			wantStatus: "findings",
		},
	}
	// Patch the "scan lows" case by hand: stubAuditResult does not
	// expose a lows count, so synthesise the low finding directly.
	cases[7].check.Scan.Findings = append(cases[7].check.Scan.Findings,
		types.Finding{Severity: scanner.SeverityLow})

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := computeAuditVerdict(tc.check, tc.threshold)
			require.NoError(t, err)
			require.Equal(t, tc.wantStatus, v.Status, "status mismatch")
			require.Equal(t, tc.wantThresholdEx, v.ThresholdExceeded, "threshold_exceeded mismatch")
		})
	}
}

func TestAuditVerdictWarningTrips(t *testing.T) {
	// computeAuditVerdict's warning threshold must trip on
	// either a check warning OR a scan high. Direct unit test
	// because building a fixture that emits a scan-high finding
	// from the audit pipeline is expensive.
	v, err := computeAuditVerdict(stubAuditResult(t, 0, 1, 0, 0, 0, 0), "warning")
	require.NoError(t, err)
	require.True(t, v.ThresholdExceeded)
	require.Equal(t, "fail", v.Status)
	require.Equal(t, 1, v.CheckWarnings)

	v, err = computeAuditVerdict(stubAuditResult(t, 0, 0, 0, 1, 0, 0), "warning")
	require.NoError(t, err)
	require.True(t, v.ThresholdExceeded, "scan high must trip warning threshold")
}

func TestAuditVerdictCriticalDoesNotTripOnWarningOnly(t *testing.T) {
	// Threshold=critical, only a warning present: gate must not
	// trip. Per #110 tri-state, Status is "findings" (findings
	// exist below the gate), NOT "pass" (which would imply zero
	// findings).
	v, err := computeAuditVerdict(stubAuditResult(t, 0, 1, 0, 0, 0, 0), "critical")
	require.NoError(t, err)
	require.False(t, v.ThresholdExceeded, "single warning must not trip critical gate")
	require.Equal(t, "findings", v.Status,
		"tri-state: findings exist below the configured threshold, so status must be 'findings', not 'pass'")
}

func TestAuditVerdictInfoTripsOnInfoFindings(t *testing.T) {
	// Codex P2 regression (PR 5 review): --fail-on info must
	// trip on INFO-level findings from either side. The earlier
	// shape only summed critical/warning for check and
	// critical/high/medium/low for scan, so an INFO-only
	// finding could pass --fail-on info cleanly. That broke the
	// "lowest threshold" contract.
	v, err := computeAuditVerdict(stubAuditResult(t, 0, 0, 0, 0, 1, 0), "info")
	require.NoError(t, err)
	require.True(t, v.ThresholdExceeded, "check INFO must trip --fail-on info")

	v, err = computeAuditVerdict(stubAuditResult(t, 0, 0, 0, 0, 0, 1), "info")
	require.NoError(t, err)
	require.True(t, v.ThresholdExceeded, "scan INFO must trip --fail-on info")
}

func TestAuditVerdictRejectsInvalidThreshold(t *testing.T) {
	// Codex P2 regression (PR 5 review): a typo in --fail-on
	// previously fell through the switch without setting
	// ThresholdExceeded and the audit exited green. scan and
	// check both reject invalid thresholds; audit must do the
	// same so a CI typo cannot silently disable the gate.
	_, err := computeAuditVerdict(stubAuditResult(t, 1, 0, 0, 0, 0, 0), "critcal") // intentional typo
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid --fail-on")
}

func TestAuditTriageTable(t *testing.T) {
	cases := []struct {
		name         string
		result       *AuditResult
		threshold    string
		wantDecision string
		wantReason   string
	}{
		{
			name:         "clean proceeds",
			result:       stubAuditResult(t, 0, 0, 0, 0, 0, 0),
			wantDecision: "proceed",
		},
		{
			name:         "check critical stops without gate",
			result:       stubAuditResult(t, 1, 0, 0, 0, 0, 0),
			wantDecision: "stop",
			wantReason:   "known_malicious_package",
		},
		{
			name:         "scan critical stops without gate",
			result:       stubAuditResult(t, 0, 0, 1, 0, 0, 0),
			wantDecision: "stop",
			wantReason:   "critical_content_finding",
		},
		{
			name:         "warnings review below critical gate",
			result:       stubAuditResult(t, 0, 1, 0, 0, 0, 0),
			threshold:    "critical",
			wantDecision: "review",
			wantReason:   "findings_present",
		},
		{
			name:         "gate exceeded stops",
			result:       stubAuditResult(t, 0, 1, 0, 0, 0, 0),
			threshold:    "warning",
			wantDecision: "stop",
			wantReason:   "gate_exceeded",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := computeAuditVerdict(tc.result, tc.threshold)
			require.NoError(t, err)
			tc.result.Verdict = v

			got := computeAuditTriage(tc.result)
			require.Equal(t, tc.wantDecision, got.Decision)
			require.NotEmpty(t, got.Summary)
			require.NotEmpty(t, got.RecommendedNextSteps)
			if tc.wantReason != "" {
				requireTriageReason(t, got, tc.wantReason)
			}
		})
	}
}

func TestAuditTriageDocumentsBaselineVisibility(t *testing.T) {
	result := stubAuditResult(t, 0, 0, 0, 0, 0, 1)
	result.Scan.Baseline = &types.BaselineSummary{
		Applied:   true,
		Total:     3,
		Baselined: 3,
	}
	result.Verdict = AuditVerdict{Status: "pass"}

	got := computeAuditTriage(result)
	require.Equal(t, "review", got.Decision)
	requireTriageReason(t, got, "baseline_existing_findings")
}

// stubAuditResult builds a minimal AuditResult with the requested
// finding counts. Used in the verdict unit tests.
func stubAuditResult(t *testing.T, checkC, checkW, scanC, scanH, checkI, scanI int) *AuditResult {
	t.Helper()
	check := &incident.CheckResult{}
	for i := 0; i < checkC; i++ {
		check.Findings = append(check.Findings, incident.Finding{Severity: incident.SevCritical})
	}
	for i := 0; i < checkW; i++ {
		check.Findings = append(check.Findings, incident.Finding{Severity: incident.SevWarning})
	}
	for i := 0; i < checkI; i++ {
		check.Findings = append(check.Findings, incident.Finding{Severity: incident.SevInfo})
	}
	scan := &scanner.ScanResult{}
	for i := 0; i < scanC; i++ {
		scan.Findings = append(scan.Findings, types.Finding{Severity: scanner.SeverityCritical})
	}
	for i := 0; i < scanH; i++ {
		scan.Findings = append(scan.Findings, types.Finding{Severity: scanner.SeverityHigh})
	}
	for i := 0; i < scanI; i++ {
		scan.Findings = append(scan.Findings, types.Finding{Severity: scanner.SeverityInfo})
	}
	return &AuditResult{Check: check, Scan: scan}
}

func requireTriageReason(t *testing.T, triage AuditTriage, kind string) {
	t.Helper()
	for _, r := range triage.Reasons {
		if r.Kind == kind {
			return
		}
	}
	t.Fatalf("expected triage reason %q in %#v", kind, triage.Reasons)
}
