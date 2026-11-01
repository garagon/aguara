package commands

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/garagon/aguara/internal/types"
	"github.com/stretchr/testify/require"
)

func TestKubePolicyCLIThresholds(t *testing.T) {
	const content = `{"apiVersion":"v1","kind":"Pod","spec":{"containers":[{"name":"app","securityContext":{"capabilities":{"add":["SETUID"]}}}]}}`
	dir := t.TempDir()
	path := filepath.Join(dir, "pod.json")
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))
	for _, tc := range []struct {
		name string
		args []string
		fail bool
	}{
		{"CI", []string{"--ci"}, false},
		{"high", []string{"--fail-on", "high"}, false},
		{"low", []string{"--fail-on", "low"}, true},
		{"info", []string{"--fail-on", "info"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetFlags()
			out := filepath.Join(t.TempDir(), "out.json")
			args := []string{"scan", path, "--format", "json", "--workers", "1", "--no-update-check", "--project-policy", "ignore", "-o", out}
			rootCmd.SetOut(new(bytes.Buffer))
			rootCmd.SetErr(new(bytes.Buffer))
			rootCmd.SetArgs(append(args, tc.args...))
			t.Cleanup(func() {
				rootCmd.SetArgs(nil)
				rootCmd.SetOut(nil)
				rootCmd.SetErr(nil)
				resetFlags()
			})
			err := rootCmd.Execute()
			if tc.fail {
				require.ErrorIs(t, err, ErrThresholdExceeded)
			} else {
				require.NoError(t, err)
			}
			data, err := os.ReadFile(out)
			require.NoError(t, err)
			var scan types.ScanResult
			require.NoError(t, json.Unmarshal(data, &scan))
			require.Len(t, scan.Findings, 1)
			require.Equal(t, "K8S_IDENTITY_CAPABILITIES_001", scan.Findings[0].RuleID)
			require.Equal(t, "context", scan.Findings[0].DecisionImpact)
			require.Equal(t, types.SeverityLow, scan.Findings[0].Severity)
			require.Equal(t, 8.0, scan.Findings[0].Score)

			audit := stubAuditResult(t, 0, 0, 0, 0, 0, 0)
			audit.Scan.Findings = scan.Findings
			audit.scanGate = scan.Findings
			audit.scanGateSet = true
			audit.Verdict, err = computeAuditVerdict(audit, "")
			require.NoError(t, err)
			audit.Triage = computeAuditTriage(audit)
			require.Equal(t, "proceed", audit.Triage.Decision)
			require.Equal(t, 1, audit.Triage.ContextObservations)
			require.Zero(t, audit.Triage.ReviewFindings)
			require.Equal(t, "allowed", computeAuditAgentHandoff(audit.Triage).Status)
		})
	}
}

func TestKubePolicyCLIEvidenceFormats(t *testing.T) {
	// Arbitrary adjacent data must not be copied into this posture observation.
	const privateValue = "DO_NOT_COPY_ADJACENT_DATA"
	const content = `{"apiVersion":"v1","kind":"Pod","spec":{"containers":[{"name":"` + privateValue + `","securityContext":{"capabilities":{"add":["SETUID"]}}}]}}`
	path := filepath.Join(t.TempDir(), "pod.json")
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))
	for _, format := range []string{"json", "sarif"} {
		t.Run(format, func(t *testing.T) {
			resetFlags()
			out := filepath.Join(t.TempDir(), "result.json")
			rootCmd.SetOut(new(bytes.Buffer))
			rootCmd.SetErr(new(bytes.Buffer))
			rootCmd.SetArgs([]string{"scan", path, "--format", format, "--workers", "1", "--no-update-check", "--project-policy", "ignore", "-o", out})
			t.Cleanup(func() {
				rootCmd.SetArgs(nil)
				rootCmd.SetOut(nil)
				rootCmd.SetErr(nil)
				resetFlags()
			})
			require.NoError(t, rootCmd.Execute())
			data, err := os.ReadFile(out)
			require.NoError(t, err)
			require.True(t, json.Valid(data))
			require.NotContains(t, string(data), privateValue)
			require.Contains(t, string(data), "spec.containers[0].securityContext.capabilities.add: SETUID")
			if format == "sarif" {
				var report struct {
					Runs []struct {
						Results []struct {
							RuleID string `json:"ruleId"`
							Level  string `json:"level"`
						} `json:"results"`
					} `json:"runs"`
				}
				require.NoError(t, json.Unmarshal(data, &report))
				require.Len(t, report.Runs, 1)
				require.Len(t, report.Runs[0].Results, 1)
				require.Equal(t, "K8S_IDENTITY_CAPABILITIES_001", report.Runs[0].Results[0].RuleID)
				require.Equal(t, "note", report.Runs[0].Results[0].Level)
			}
		})
	}
}
