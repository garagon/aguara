package output_test

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"

	"github.com/garagon/aguara/internal/output"
	"github.com/garagon/aguara/internal/types"
)

const longName = "Claude Code settings inject a code-execution environment variable into every session"

func layoutResult() *types.ScanResult {
	return &types.ScanResult{
		FilesScanned: 2,
		RulesLoaded:  191,
		Suppressed:   &types.SuppressionSummary{Deduplicated: 3, BelowMinSeverity: 1},
		Findings: []types.Finding{
			{
				RuleID: "AGENTCFG_HELPER_REPO_SCRIPT_001", RuleName: longName, Severity: types.SeverityCritical,
				FilePath: ".claude/settings.json", Line: 3, MatchedText: strings.Repeat("evidence ", 20) + "END",
				Remediation: strings.Repeat("remediation words ", 10) + "DONE",
				AlsoMatched: []types.MergedFinding{
					{RuleID: "AGENTCFG_ENV_EXEC_001", Severity: types.SeverityHigh},
					{RuleID: "CRED_011", Severity: types.SeverityMedium},
				},
			},
			{
				RuleID: "SHELL_UNSAFE_NPM_SOURCE_001", RuleName: "Unencrypted npm dependency source in a script",
				Severity: types.SeverityMedium, FilePath: "install.sh", Line: 9,
				MatchedText: "npm install http://registry.example/pkg.tgz", Remediation: "Use https.",
			},
		},
	}
}

func render(t *testing.T, f output.TerminalFormatter) string {
	t.Helper()
	t.Setenv("NO_COLOR", "")
	f.NoColor = true
	var buf bytes.Buffer
	require.NoError(t, f.Format(&buf, layoutResult()))
	return buf.String()
}

func TestTerminalNeverCutsRuleIDsOrNames(t *testing.T) {
	for _, width := range []int{0, 60, 100} {
		out := render(t, output.TerminalFormatter{Width: width, Verbose: true})
		require.Contains(t, out, "AGENTCFG_HELPER_REPO_SCRIPT_001", width)
		require.Contains(t, out, "SHELL_UNSAFE_NPM_SOURCE_001", width)
		flat := strings.Join(strings.Fields(out), " ")
		require.Contains(t, flat, longName, "the rule name is complete (wrapped, not cut) at width %d", width)
		require.Contains(t, flat, "END", "verbose evidence is not truncated")
		require.Contains(t, flat, "DONE")
		require.NotContains(t, out, "...", "nothing is truncated at width %d", width)
		if width > 0 {
			for _, line := range strings.Split(out, "\n") {
				require.LessOrEqual(t, utf8.RuneCountInString(line), width, "line wider than the terminal: %q", line)
			}
		}
	}
}

func TestTerminalDefaultKeepsEvidencePreviewAndHints(t *testing.T) {
	out := render(t, output.TerminalFormatter{})
	require.Contains(t, out, "...", "without -v the CRITICAL evidence stays a preview")
	require.Contains(t, out, "+2 more on this line: AGENTCFG_ENV_EXEC_001, CRED_011")
	require.Contains(t, out, "not listed separately: 3 merged into findings on the same line")
	require.Contains(t, out, "1 below the minimum severity")
	require.Contains(t, out, "Run with -v to show evidence and fixes for every finding.")
	require.NotContains(t, out, "Use https.", "non-critical fixes still need -v")

	verbose := render(t, output.TerminalFormatter{Verbose: true})
	require.Contains(t, verbose, "npm install http://registry.example/pkg.tgz", "-v shows evidence below CRITICAL")
	require.Contains(t, verbose, "Fix: Use https.")
	require.NotContains(t, verbose, "Run with -v")
}

func TestTerminalHeaderDistinguishesDetectionsFromPatternRules(t *testing.T) {
	out := render(t, output.TerminalFormatter{Detections: 259})
	require.Contains(t, out, "259 detections (191 pattern rules)")
	require.Contains(t, out, "2 findings · 259 detections")
	out = render(t, output.TerminalFormatter{})
	require.Contains(t, out, "191 pattern rules", "without the catalog size the pattern count is labelled")
}

func TestMarkdownNamesMergedFindings(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, (&output.MarkdownFormatter{Detections: 259}).Format(&buf, layoutResult()))
	out := buf.String()
	require.Contains(t, out, "259 detections (191 pattern rules)")
	require.Contains(t, out, "(+2 more on this line: `AGENTCFG_ENV_EXEC_001`, `CRED_011`)")
	require.Contains(t, out, "not listed separately")
}
