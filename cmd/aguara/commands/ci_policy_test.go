package commands

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDetectedCIVarNamesTheMatchingVariable(t *testing.T) {
	clearCIEnv(t)
	require.Empty(t, detectedCIVar())
	require.False(t, isCI())
	t.Setenv("CI", "false")
	require.Empty(t, detectedCIVar(), "CI=false is not a CI environment")
	t.Setenv("TEAMCITY_VERSION", "2024.03")
	require.Equal(t, "TEAMCITY_VERSION", detectedCIVar())
	t.Setenv("CI", "1")
	require.Equal(t, "CI", detectedCIVar())
	require.True(t, isCI())
}

// runScanInCI runs a JSON scan of dir with the given CI variable set and
// returns the report, stderr and the command error.
func runScanInCI(t *testing.T, ciVar, ciValue, dir string, args ...string) ([]byte, string, error) {
	t.Helper()
	clearCIEnv(t)
	if ciVar != "" {
		t.Setenv(ciVar, ciValue)
	}
	var data []byte
	var err error
	stderr := captureStderrBytes(t, func() {
		data, err = runScanJSONWithError(t, dir, args...)
	})
	return data, string(stderr), err
}

// v0.29.0 applied a project's `fail_on: high` in CI. Ignoring project
// policy in CI must not silently drop that gate: a failure threshold can
// only add one, so it still applies, and the notice says so.
func TestCIScanKeepsProjectFailOnGate(t *testing.T) {
	dir := projectWith(t, map[string]string{
		".aguara.yml": "fail_on: high\n",
		"payload.md":  injectionPayload, // CRITICAL
	})
	_, stderr, err := runScanInCI(t, "CI", "true", dir)
	require.ErrorIs(t, err, ErrThresholdExceeded, "the project's fail_on gate must still fail the run")
	require.Contains(t, stderr, "notice: CI environment detected (CI)")
	require.Contains(t, stderr, "applying fail_on: high from "+filepath.Join(dir, ".aguara.yml"))
	require.NotContains(t, stderr, "not applying", "fail_on was the only setting")
}

// Settings that can hide findings or change the report stay unapplied
// in CI, and the notice names each of them. A developer with CI=1
// exported locally sees the same notice.
func TestCINoticeNamesSkippedProjectPolicy(t *testing.T) {
	rules := t.TempDir()
	dir := projectWith(t, map[string]string{
		".aguara.yml":   "fail_on: critical\nformat: sarif\nrules: " + rules + "\ndisable_rules:\n  - PROMPT_INJECTION_001\nignore:\n  - payload.md\n",
		".aguaraignore": "# comment\npayload.md\n",
		"payload.md":    injectionPayload,
	})
	data, stderr, err := runScanInCI(t, "CI", "1", dir)
	require.ErrorIs(t, err, ErrThresholdExceeded, "fail_on: critical applies and the CRITICAL finding is reported")
	require.Contains(t, string(data), `"rule_id": "PROMPT_INJECTION_001"`)
	// format is not listed: this run passed --format json, which wins.
	require.Contains(t, stderr, "notice: CI environment detected (CI); not applying policy owned by the scanned project: "+
		filepath.Join(dir, ".aguara.yml")+" (ignore, disable_rules, rules), "+filepath.Join(dir, ".aguaraignore")+
		" (pass --project-policy trust if the pipeline owns these files); applying fail_on: critical")

	// Without --format, the config's sarif would have applied: the run
	// prints the terminal report and the notice says format was skipped.
	out := filepath.Join(t.TempDir(), "report")
	stderrBytes := captureStderrBytes(t, func() {
		require.ErrorIs(t, runCLI(t, "scan", dir, "-o", out), ErrThresholdExceeded)
	})
	require.Contains(t, string(stderrBytes), "(ignore, disable_rules, rules, format)")
	report, err := os.ReadFile(out)
	require.NoError(t, err)
	require.Contains(t, string(report), "AGUARA SCAN")
}

// A project .aguara.yml that is not applied is not validated either:
// unknown keys, unknown rule IDs, invalid override severities and a
// missing rules directory produce no warning and no error in CI, because
// nothing from those settings runs. Only fail_on is read, and the notice
// lists the rest as not applied. audit, which ignores the file by
// default, is just as quiet.
func TestCIIgnoredProjectConfigIsNotValidated(t *testing.T) {
	broken := "fail_on: critical\n" +
		"disabled_rules:\n  - PROMPT_INJECTION_001\n" +
		"rules: ./missing-rules\n" +
		"disable_rules:\n  - TYPO_001\n" +
		"rule_overrides:\n  NOPE_002:\n    disabled: true\n  CRED_002:\n    severity: SEVERE\n    severty: low\n"
	dir := projectWith(t, map[string]string{".aguara.yml": broken, "payload.md": injectionPayload})

	data, stderr, err := runScanInCI(t, "GITHUB_ACTIONS", "true", dir)
	require.ErrorIs(t, err, ErrThresholdExceeded, "fail_on: critical still gates the CRITICAL finding")
	require.Contains(t, string(data), `"rule_id": "PROMPT_INJECTION_001"`)
	require.NotContains(t, stderr, "warning:")
	require.NotContains(t, stderr, "Error")
	require.Contains(t, stderr, filepath.Join(dir, ".aguara.yml")+" (disable_rules, rule_overrides, rules)")
	require.Contains(t, stderr, "applying fail_on: critical")

	t.Setenv("HOME", t.TempDir())
	out := filepath.Join(t.TempDir(), "audit.json")
	stderrBytes := captureStderrBytes(t, func() {
		_ = runCLI(t, "audit", dir, "--format", "json", "-o", out)
	})
	require.NotContains(t, string(stderrBytes), "warning:")
	_, statErr := os.Stat(out)
	require.NoError(t, statErr, "audit writes its report")
}

// The notice names the variable that matched.
func TestCINoticeNamesDetectedVariable(t *testing.T) {
	dir := projectWith(t, selfSuppressingProjects["aguaraignore"])
	_, stderr, err := runScanInCI(t, "GITHUB_ACTIONS", "true", dir, "--fail-on", "high")
	require.ErrorIs(t, err, ErrThresholdExceeded)
	require.Contains(t, stderr, "notice: CI environment detected (GITHUB_ACTIONS); not applying policy owned by the scanned project: "+filepath.Join(dir, ".aguaraignore"))
}

// An explicit --fail-on wins over the project's fail_on, as it does in a
// trusted run, so nothing about fail_on is applied or reported.
func TestCIExplicitFailOnOverridesProjectFailOn(t *testing.T) {
	dir := projectWith(t, map[string]string{
		".aguara.yml": "fail_on: low\n",
		"notes.md":    "# Notes\nRun the tests before pushing.\n",
	})
	_, stderr, err := runScanInCI(t, "CI", "true", dir, "--fail-on", "critical")
	require.NoError(t, err)
	require.NotContains(t, stderr, "notice:")
}

// --ci and --project-policy ignore are explicit choices: no notice, and
// the project's fail_on does not apply (--ci sets its own gate).
func TestCIExplicitPolicyChoicesPrintNoCINotice(t *testing.T) {
	dir := projectWith(t, map[string]string{
		".aguara.yml": "fail_on: low\n",
		"notes.md":    "# Notes\nRun the tests before pushing.\n",
	})
	for _, args := range [][]string{{"--ci"}, {"--project-policy", "ignore"}} {
		_, stderr, err := runScanInCI(t, "CI", "true", dir, args...)
		require.NoError(t, err, "%v: the project's fail_on: low must not apply", args)
		require.NotContains(t, stderr, "CI environment detected", "%v", args)
	}
}

// An unreadable gate fails closed and names the file.
func TestCIInvalidProjectFailOnIsAnError(t *testing.T) {
	dir := projectWith(t, map[string]string{".aguara.yml": "fail_on: hgih\n", "notes.md": "# notes\n"})
	_, _, err := runScanInCI(t, "CI", "true", dir)
	requireUsageError(t, err, filepath.Join(dir, ".aguara.yml")+`: invalid fail_on "hgih"`)
}

// Without project policy there is nothing to report.
func TestCIScanWithoutProjectPolicyPrintsNoNotice(t *testing.T) {
	dir := projectWith(t, map[string]string{
		".aguara.yml":   "severity: info\nformat: terminal\n", // defaults only
		".aguaraignore": "# nothing here\n",
		"notes.md":      "# notes\n",
	})
	_, stderr, err := runScanInCI(t, "CI", "true", dir)
	require.NoError(t, err)
	require.NotContains(t, stderr, "notice:")
}

// A local run without CI variables keeps applying the whole config.
func TestLocalScanStillAppliesWholeProjectConfig(t *testing.T) {
	dir := projectWith(t, map[string]string{
		".aguara.yml": "fail_on: high\ndisable_rules:\n  - PROMPT_INJECTION_001\n",
		"payload.md":  injectionPayload,
	})
	_, stderr, err := runScanInCI(t, "", "", dir)
	require.NoError(t, err, "disable_rules applies locally, so nothing reaches the gate")
	require.Contains(t, stderr, "notice: applied policy owned by the scanned project: "+filepath.Join(dir, ".aguara.yml")+" (disable_rules, fail_on)")
	_, err = os.Stat(filepath.Join(dir, ".aguara.yml"))
	require.NoError(t, err)
}
