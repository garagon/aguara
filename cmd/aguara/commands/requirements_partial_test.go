package commands

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/garagon/aguara/internal/incident"
	"github.com/stretchr/testify/require"
)

// gateRun runs `aguara <cmd> <dir> --ci` with JSON output and returns the
// command's error (ErrThresholdExceeded is exit 1) and the report.
func gateRun(t *testing.T, cmd, dir string) (error, []byte) {
	t.Helper()
	resetFlags()
	out := filepath.Join(t.TempDir(), cmd+".json")
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{cmd, dir, "--ci", "--format", "json", "-o", out, "--no-update-check"})
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		resetFlags()
	})
	err := rootCmd.Execute()
	data, readErr := os.ReadFile(out)
	require.NoError(t, readErr)
	return err, data
}

func gateCheck(t *testing.T, dir string) (error, *incident.CheckResult) {
	t.Helper()
	err, data := gateRun(t, "check", dir)
	var res incident.CheckResult
	require.NoError(t, json.Unmarshal(data, &res))
	return err, &res
}

func gateAudit(t *testing.T, dir string) (error, *AuditResult) {
	t.Helper()
	err, data := gateRun(t, "audit", dir)
	var res AuditResult
	require.NoError(t, json.Unmarshal(data, &res))
	return err, &res
}

// pip accepts an unambiguous prefix of a long option. A compromised pin
// beside such an option is still read and fails both gates.
func TestAbbreviatedPipOptionsDoNotHideAPin(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AGUARA_NO_UPDATE_CHECK", "1")
	for _, line := range []string{
		"--extra-index https://example.invalid/simple",
		"--index https://example.invalid/simple",
		"--find ./wheels",
		"--pref",
		"--use-f fast-deps",
		"--edit ./x",
		"--constr other.txt",
	} {
		t.Run(line, func(t *testing.T) {
			dir := projectWith(t, map[string]string{
				"requirements.txt": line + "\nnum2words==0.5.15\n",
				"other.txt":        "six==1.16.0\n",
			})
			err, check := gateCheck(t, dir)
			require.ErrorIs(t, err, ErrThresholdExceeded, "check --ci exits 1")
			requireCriticalFor(t, check.Findings, "num2words")
			for _, u := range check.Coverage.UnsupportedEvidence {
				require.NotEqual(t, "format_not_parsed", u.Reason, "pip reads the option, so the file is read in full")
			}

			err, audit := gateAudit(t, dir)
			require.ErrorIs(t, err, ErrThresholdExceeded, "audit --ci exits 1")
			require.Equal(t, "stop", audit.Triage.Decision)
		})
	}
}

// A line pip also rejects is skipped and reported, and the pins on the
// other lines are still matched.
func TestRequirementsLinePipRejectsDoesNotHideThePins(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AGUARA_NO_UPDATE_CHECK", "1")
	dir := projectWith(t, map[string]string{"requirements.txt": "num2words==0.5.15\n--frobnicate\n"})

	err, check := gateCheck(t, dir)
	require.ErrorIs(t, err, ErrThresholdExceeded)
	requireCriticalFor(t, check.Findings, "num2words")
	require.Len(t, check.Coverage.UnsupportedEvidence, 1)
	u := check.Coverage.UnsupportedEvidence[0]
	require.Equal(t, "format_not_parsed", u.Reason)
	require.Equal(t, filepath.Join(dir, "requirements.txt"), u.Path)
	require.Contains(t, u.Detail, "line 2")
	require.Len(t, check.Coverage.PackageEvidence, 1, "the file was read")

	err, audit := gateAudit(t, dir)
	require.ErrorIs(t, err, ErrThresholdExceeded)
	require.Equal(t, "stop", audit.Triage.Decision)
}

// With no parsed pin matching, check passes and audit asks for review.
func TestRequirementsLinePipRejectsWithoutAMatchIsReview(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AGUARA_NO_UPDATE_CHECK", "1")
	dir := projectWith(t, map[string]string{"requirements.txt": "six==1.16.0\n--frobnicate\n"})

	err, check := gateCheck(t, dir)
	require.NoError(t, err)
	require.Empty(t, check.Findings)
	require.Len(t, check.Coverage.UnsupportedEvidence, 1)
	require.Equal(t, "format_not_parsed", check.Coverage.UnsupportedEvidence[0].Reason)

	err, audit := gateAudit(t, dir)
	require.NotErrorIs(t, err, ErrThresholdExceeded)
	require.Equal(t, "review", audit.Triage.Decision)
	requireTriageReason(t, audit.Triage, "partial_dependency_coverage")
	require.False(t, audit.Plan.CanInstallDependencies)
}

// A pip file under a name discovery does not read keeps its exact pins
// matched when one of its lines is outside the grammar; a text file under
// such a name that pins nothing is not a pip file.
func TestUnreadRequirementsNameWithALineOutsideTheGrammar(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AGUARA_NO_UPDATE_CHECK", "1")
	dir := projectWith(t, map[string]string{
		"requirements/dev.txt":   "num2words==0.5.15\n--frobnicate\n",
		"requirements/notes.txt": "Install\n=======\n",
	})
	err, check := gateCheck(t, dir)
	require.ErrorIs(t, err, ErrThresholdExceeded)
	requireCriticalFor(t, check.Findings, "num2words")
	require.Len(t, check.Coverage.UnsupportedEvidence, 1)
	require.Equal(t, filepath.Join(dir, "requirements", "dev.txt"), check.Coverage.UnsupportedEvidence[0].Path)
	require.Equal(t, "requirements_name_not_read", check.Coverage.UnsupportedEvidence[0].Reason)
}

func requireCriticalFor(t *testing.T, findings []incident.Finding, name string) {
	t.Helper()
	for _, f := range findings {
		if f.Severity == incident.SevCritical && bytes.Contains([]byte(f.Title), []byte(name)) {
			return
		}
	}
	t.Fatalf("no CRITICAL finding for %s in %#v", name, findings)
}
