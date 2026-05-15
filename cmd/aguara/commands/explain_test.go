package commands

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/rulemeta"
	"github.com/stretchr/testify/require"
)

func TestExplainKnownRule(t *testing.T) {
	buf := new(bytes.Buffer)
	resetFlags()
	flagNoColor = true
	t.Cleanup(resetFlags)

	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"explain", "PROMPT_INJECTION_001", "--no-color"})
	defer rootCmd.SetArgs(nil)
	defer rootCmd.SetOut(nil)

	err := rootCmd.Execute()
	require.NoError(t, err)

	out := buf.String()
	require.Contains(t, out, "PROMPT_INJECTION_001")
	require.Contains(t, out, "CRITICAL")
	require.Contains(t, out, "prompt-injection")
	require.Contains(t, out, "Patterns:")
	require.Contains(t, out, "True Positives:")
}

func TestExplainJSON(t *testing.T) {
	buf := new(bytes.Buffer)
	resetFlags()
	t.Cleanup(resetFlags)

	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"explain", "PROMPT_INJECTION_001", "--format", "json"})
	defer rootCmd.SetArgs(nil)
	defer rootCmd.SetOut(nil)

	err := rootCmd.Execute()
	require.NoError(t, err)

	var info rulemeta.Rule
	require.NoError(t, json.Unmarshal(buf.Bytes(), &info))
	require.Equal(t, "PROMPT_INJECTION_001", info.ID)
	require.Equal(t, "CRITICAL", info.Severity)
	require.Equal(t, "prompt-injection", info.Category)
	require.Empty(t, info.Analyzer, "YAML pattern rules have no analyzer; omitempty must keep the field absent")
	require.NotEmpty(t, info.Patterns)
	require.NotEmpty(t, info.TruePositives)
}

func TestExplainAnalyzerRuleJSON(t *testing.T) {
	// QA regression on v0.16.0: scan emitted JS_DNS_TXT_EXFIL_001
	// but explain failed with "rule not found" because analyzer
	// rules weren't in the catalog. This test locks the new path:
	// the analyzer rule resolves AND its JSON shape carries the
	// analyzer field so downstream tooling can branch on it.
	buf := new(bytes.Buffer)
	resetFlags()
	t.Cleanup(resetFlags)

	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"explain", "JS_DNS_TXT_EXFIL_001", "--format", "json"})
	defer rootCmd.SetArgs(nil)
	defer rootCmd.SetOut(nil)

	err := rootCmd.Execute()
	require.NoError(t, err)

	var info rulemeta.Rule
	require.NoError(t, json.Unmarshal(buf.Bytes(), &info))
	require.Equal(t, "JS_DNS_TXT_EXFIL_001", info.ID)
	require.Equal(t, rulemeta.AnalyzerJSRisk, info.Analyzer)
	require.Equal(t, "supply-chain", info.Category)
	require.NotEmpty(t, info.Description)
	require.NotEmpty(t, info.Remediation)
}

func TestExplainAnalyzerRuleTerminal(t *testing.T) {
	// Terminal output for analyzer rules must print the new
	// Analyzer: line so a human reading the explain block can
	// see which engine owns the rule.
	buf := new(bytes.Buffer)
	resetFlags()
	flagNoColor = true
	t.Cleanup(resetFlags)

	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"explain", "GHA_PWN_REQUEST_001", "--no-color"})
	defer rootCmd.SetArgs(nil)
	defer rootCmd.SetOut(nil)

	err := rootCmd.Execute()
	require.NoError(t, err)

	out := buf.String()
	require.Contains(t, out, "GHA_PWN_REQUEST_001")
	require.True(t, strings.Contains(out, "Analyzer:") && strings.Contains(out, rulemeta.AnalyzerCITrust),
		"analyzer rule terminal output must print the Analyzer: line; got: %s", out)
}

func TestExplainCaseInsensitive(t *testing.T) {
	buf := new(bytes.Buffer)
	resetFlags()
	t.Cleanup(resetFlags)

	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"explain", "js_dns_txt_exfil_001", "--format", "json"})
	defer rootCmd.SetArgs(nil)
	defer rootCmd.SetOut(nil)

	err := rootCmd.Execute()
	require.NoError(t, err)

	var info rulemeta.Rule
	require.NoError(t, json.Unmarshal(buf.Bytes(), &info))
	require.Equal(t, "JS_DNS_TXT_EXFIL_001", info.ID, "explain must be case-insensitive on the ID arg")
}

func TestExplainNotFound(t *testing.T) {
	buf := new(bytes.Buffer)
	resetFlags()
	t.Cleanup(resetFlags)

	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"explain", "NONEXISTENT_999"})
	defer rootCmd.SetArgs(nil)
	defer rootCmd.SetOut(nil)
	defer rootCmd.SetErr(nil)

	err := rootCmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
	// SilenceUsage must prevent Cobra from dumping the --help
	// block on rule-not-found. The buf captures stderr too, so a
	// regression that re-enables Usage would appear here.
	require.NotContains(t, buf.String(), "Usage:",
		"rule-not-found must not print Cobra Usage block")
	require.NotContains(t, buf.String(), "Flags:",
		"rule-not-found must not print Cobra Flags block")
}

func TestListRulesIncludesAnalyzerRules(t *testing.T) {
	// JSON list-rules must include analyzer-emitted rules
	// alongside YAML rules so a CI integrator scripting against
	// list-rules JSON sees every ID the scanner can emit.
	buf := new(bytes.Buffer)
	resetFlags()
	t.Cleanup(resetFlags)

	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"list-rules", "--format", "json"})
	defer rootCmd.SetArgs(nil)
	defer rootCmd.SetOut(nil)

	err := rootCmd.Execute()
	require.NoError(t, err)

	var entries []rulemeta.Rule
	require.NoError(t, json.Unmarshal(buf.Bytes(), &entries))

	ids := make(map[string]string, len(entries))
	for _, e := range entries {
		ids[e.ID] = e.Analyzer
	}
	for _, want := range []string{
		"JS_DNS_TXT_EXFIL_001",
		"GHA_PWN_REQUEST_001",
		"NPM_LIFECYCLE_GIT_001",
		"TOXIC_001",
		"NLP_HIDDEN_INSTRUCTION",
		"PROMPT_INJECTION_001",
	} {
		_, ok := ids[want]
		require.Truef(t, ok, "list-rules JSON must include %s", want)
	}
	// And one specific analyzer pin to lock the shape.
	require.Equal(t, rulemeta.AnalyzerJSRisk, ids["JS_DNS_TXT_EXFIL_001"])
}
