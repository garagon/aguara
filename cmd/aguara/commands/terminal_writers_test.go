package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/garagon/aguara/internal/incident"
	"github.com/garagon/aguara/internal/intel"
	"github.com/garagon/aguara/internal/packagecheck"
	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests cover the terminal writers and pure CLI helpers that
// scanToFile-style tests cannot reach: the writers print via fmt to
// os.Stdout (not cobra's SetOut), so they use captureStdout from
// status_test.go. All of them call resetFlags() first because the
// writers read package-level flag vars.

func TestCheckFailOnThresholdFindings(t *testing.T) {
	resetFlags()

	// No --fail-on set: never gates.
	flagFailOn = ""
	require.NoError(t, checkFailOnThresholdFindings([]scanner.Finding{{Severity: scanner.SeverityCritical}}))

	// Invalid threshold: explicit error, never a silent pass.
	flagFailOn = "critcal" // intentional typo
	err := checkFailOnThresholdFindings(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid --fail-on")

	// Below the gate.
	flagFailOn = "critical"
	require.NoError(t, checkFailOnThresholdFindings([]scanner.Finding{{Severity: scanner.SeverityHigh}}))

	// At the gate: trips with ErrThresholdExceeded.
	err = checkFailOnThresholdFindings([]scanner.Finding{{Severity: scanner.SeverityCritical}})
	require.ErrorIs(t, err, ErrThresholdExceeded)

	// The ScanResult wrapper delegates to the findings gate.
	err = checkFailOnThreshold(&scanner.ScanResult{Findings: []types.Finding{{Severity: scanner.SeverityCritical}}})
	require.ErrorIs(t, err, ErrThresholdExceeded)

	resetFlags()
}

func TestTopScanRule(t *testing.T) {
	assert.Equal(t, "", topScanRule(nil))
	assert.Equal(t, "HIGH_RULE", topScanRule([]scanner.Finding{
		{RuleID: "LOW_RULE", Severity: scanner.SeverityLow},
		{RuleID: "HIGH_RULE", Severity: scanner.SeverityHigh},
		{RuleID: "MED_RULE", Severity: scanner.SeverityMedium},
	}))
}

func TestSingleEcoEnvLabel(t *testing.T) {
	cases := map[string]string{
		ecoPython:   "Python environment",
		ecoNPM:      "npm dependencies",
		"":          "",
		"multi-eco": "",
	}
	for token, want := range cases {
		got := singleEcoEnvLabel(token)
		if want == "" {
			assert.Equal(t, "", got, "token %q", token)
		} else {
			assert.Equal(t, want, got, "token %q", token)
		}
	}
	// Every packagecheck ecosystem must produce a non-empty label so
	// the terminal header never renders an empty slot.
	for _, token := range []string{ecoGo, ecoCargo, ecoComposer, ecoRuby, ecoMaven, ecoNuGet} {
		assert.NotEmpty(t, singleEcoEnvLabel(token), "token %q", token)
	}
}

func TestEcosystemFindingText(t *testing.T) {
	hit := packagecheck.Hit{
		Ref:    packagecheck.PackageRef{Name: "evil-pkg", Version: "1.2.3"},
		Record: intel.Record{ID: "MAL-2026-0001"},
	}
	// Every ecosystem token must yield a title naming the package and
	// a remediation the user can act on; no token may fall through to
	// an empty pair.
	for _, token := range []string{ecoGo, ecoCargo, ecoComposer, ecoRuby, ecoMaven, ecoNuGet, ecoNPM, ecoPython} {
		title, remediation := ecosystemFindingText(token, hit)
		assert.Contains(t, title, "evil-pkg", "token %q", token)
		assert.Contains(t, title, "MAL-2026-0001", "token %q", token)
		assert.NotEmpty(t, remediation, "token %q", token)
	}
}

func TestIntelSourceLabel(t *testing.T) {
	cases := map[string]string{
		"embedded":       "embedded",
		"local":          "local",
		"local-verified": "local verified",
		"remote-fresh":   "remote (fresh)",
		"":               "embedded",
		"future-mode":    "future-mode",
	}
	for in, want := range cases {
		assert.Equal(t, want, intelSourceLabel(in), "snapshot %q", in)
	}
}

func TestPrintIntelFreshnessWritesStdout(t *testing.T) {
	resetFlags()
	fetch, restore := captureStdout(t)
	defer restore()

	printIntelFreshness(incident.IntelSummary{
		Snapshot:    "embedded",
		GeneratedAt: time.Now().Add(-48 * time.Hour),
		AgeDays:     2,
	}, false)

	out := fetch()
	require.Contains(t, out, "embedded", "non-CI mode must print the provenance line to stdout")
}

func TestApplyAuditCIDefaults(t *testing.T) {
	resetFlags()
	t.Setenv("NO_COLOR", "")

	// --ci implies --fail-on critical and no color.
	flagAuditCI = true
	applyAuditCIDefaults()
	assert.Equal(t, "critical", flagAuditFailOn)
	assert.True(t, flagNoColor)

	// An explicit --fail-on wins over the CI default.
	resetFlags()
	flagAuditCI = true
	flagAuditFailOn = "warning"
	applyAuditCIDefaults()
	assert.Equal(t, "warning", flagAuditFailOn)

	// NO_COLOR alone disables color without touching the gate.
	resetFlags()
	t.Setenv("NO_COLOR", "1")
	applyAuditCIDefaults()
	assert.True(t, flagNoColor)
	assert.Empty(t, flagAuditFailOn)

	resetFlags()
}

func TestWriteAuditTerminal(t *testing.T) {
	resetFlags()
	flagNoColor = true

	// Clean pass: OK lines plus a green verdict, no Next hint.
	clean := stubAuditResult(t, 0, 0, 0, 0, 0, 0)
	clean.Target = "/tmp/clean"
	v, err := computeAuditVerdict(clean, "critical")
	require.NoError(t, err)
	clean.Verdict = v
	clean.Triage = computeAuditTriage(clean)
	clean.Handoff = computeAuditAgentHandoff(clean.Triage)

	fetch, restore := captureStdout(t)
	require.NoError(t, writeAuditTerminal(clean))
	restore()
	out := fetch()
	require.Contains(t, out, "AGUARA AUDIT")
	require.Contains(t, out, "Target: /tmp/clean")
	require.Contains(t, out, "No known-compromised packages")
	require.Contains(t, out, "No content findings")
	require.Contains(t, out, "Verdict: PASS")
	require.Contains(t, out, "Triage: PROCEED")
	require.Contains(t, out, "Agent handoff: ALLOWED")
	require.NotContains(t, out, "Next: aguara explain")

	// Findings on both sides + threshold exceeded: red verdict path,
	// capped scan listing, Next hint from the top rule.
	resetFlags()
	flagNoColor = true
	bad := stubAuditResult(t, 1, 1, 1, 0, 0, 0)
	bad.Target = "/tmp/bad"
	bad.Check.Findings[0].Title = "evil-pkg 1.0.0 is a known compromised package"
	bad.Check.Findings[0].Path = "/tmp/bad/node_modules/evil-pkg"
	bad.Scan.Findings[0].RuleID = "SUPPLY_003"
	bad.Scan.Findings[0].RuleName = "Download-and-execute"
	v, err = computeAuditVerdict(bad, "critical")
	require.NoError(t, err)
	bad.Verdict = v
	bad.Triage = computeAuditTriage(bad)
	bad.Handoff = computeAuditAgentHandoff(bad.Triage)

	fetch, restore = captureStdout(t)
	require.NoError(t, writeAuditTerminal(bad))
	restore()
	out = fetch()
	require.Contains(t, out, "evil-pkg 1.0.0")
	require.Contains(t, out, "SUPPLY_003")
	require.Contains(t, out, "Verdict: FAIL")
	require.Contains(t, out, "Triage: STOP")
	require.Contains(t, out, "Agent handoff: BLOCKED")
	require.Contains(t, out, "Next: aguara explain SUPPLY_003")

	resetFlags()
}

func TestWriteAuditTerminalCapsScanListing(t *testing.T) {
	resetFlags()
	flagNoColor = true

	res := stubAuditResult(t, 0, 0, 0, 0, 0, 0)
	res.Target = "/tmp/noisy"
	for i := 0; i < 15; i++ {
		res.Scan.Findings = append(res.Scan.Findings,
			types.Finding{RuleID: "LOW_RULE", Severity: scanner.SeverityLow})
	}
	v, err := computeAuditVerdict(res, "critical")
	require.NoError(t, err)
	res.Verdict = v

	fetch, restore := captureStdout(t)
	require.NoError(t, writeAuditTerminal(res))
	restore()
	out := fetch()
	require.Contains(t, out, "+5 more", "listing must cap at 10 without --verbose")

	// --verbose lifts the cap.
	resetFlags()
	flagNoColor = true
	flagAuditVerbose = true
	fetch, restore = captureStdout(t)
	require.NoError(t, writeAuditTerminal(res))
	restore()
	require.NotContains(t, fetch(), "+5 more")

	resetFlags()
}

func TestWriteCheckTerminal(t *testing.T) {
	resetFlags()
	flagNoColor = true

	// Empty result: OK line, no findings sections.
	fetch, restore := captureStdout(t)
	require.NoError(t, writeCheckTerminal(&incident.CheckResult{}, checkPlan{}))
	restore()
	out := fetch()
	require.Contains(t, out, "AGUARA CHECK")
	require.Contains(t, out, "No known-compromised packages")

	// Findings + at-risk credentials: full sections render.
	res := &incident.CheckResult{
		Environment:  "test-env",
		PackagesRead: 3,
		Findings: []incident.Finding{{
			Severity: incident.SevCritical,
			Title:    "evil-pkg 1.0.0 is a known compromised package",
			Path:     "/tmp/x/node_modules/evil-pkg",
			Detail:   "matched intel record MAL-2026-0001",
		}},
		Credentials: []incident.CredentialFile{{
			Path: "~/.npmrc", Exists: true, Guidance: "rotate npm tokens",
		}},
	}
	fetch, restore = captureStdout(t)
	require.NoError(t, writeCheckTerminal(res, checkPlan{}))
	restore()
	out = fetch()
	require.Contains(t, out, "evil-pkg 1.0.0")
	require.Contains(t, out, "CREDENTIALS AT RISK")
	require.Contains(t, out, "ACTION REQUIRED")

	resetFlags()
}

func TestWriteCleanJSONToFile(t *testing.T) {
	resetFlags()
	out := filepath.Join(t.TempDir(), "clean.json")
	flagOutput = out

	res := &incident.CleanResult{
		QuarantineDir: "/tmp/q",
		DryRun:        true,
		Actions: []incident.CleanAction{
			{Type: "delete", Target: "/tmp/x/evil.pth", Done: true},
		},
	}
	require.NoError(t, writeCleanJSON(res))

	data, err := os.ReadFile(out)
	require.NoError(t, err)
	var decoded incident.CleanResult
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.True(t, decoded.DryRun)
	require.Len(t, decoded.Actions, 1)
	assert.Equal(t, "delete", decoded.Actions[0].Type)

	resetFlags()
}

func TestWriteCleanTerminal(t *testing.T) {
	resetFlags()
	flagNoColor = true

	res := &incident.CleanResult{
		QuarantineDir: "/tmp/q",
		Actions: []incident.CleanAction{
			{Type: "delete", Target: "/tmp/x/evil.pth", Done: true},
			{Type: "uninstall", Target: "evil-pkg", Error: "pip not found"},
			{Type: "disable", Target: "evil.service", Done: false},
		},
	}
	fetch, restore := captureStdout(t)
	require.NoError(t, writeCleanTerminal(res))
	restore()
	out := fetch()
	require.Contains(t, out, "Cleaned 1/3 issues")
	require.Contains(t, out, "pip not found")

	resetFlags()
}

func TestRunCleanNoFindings(t *testing.T) {
	resetFlags()
	flagCheckPath = t.TempDir() // empty dir: nothing to clean

	fetch, restore := captureStdout(t)
	err := runClean(cleanCmd, nil)
	restore()
	require.NoError(t, err)
	require.Contains(t, fetch(), "No compromised packages")

	resetFlags()
}

func TestWriteAuditTerminalStrings(t *testing.T) {
	// Sanity: the writers must never emit the raw placeholder used by
	// redaction as a formatting artifact.
	resetFlags()
	flagNoColor = true
	res := stubAuditResult(t, 0, 0, 0, 0, 0, 0)
	v, err := computeAuditVerdict(res, "critical")
	require.NoError(t, err)
	res.Verdict = v

	fetch, restore := captureStdout(t)
	require.NoError(t, writeAuditTerminal(res))
	restore()
	assert.False(t, strings.Contains(fetch(), "%!"), "no fmt formatting artifacts")

	resetFlags()
}
