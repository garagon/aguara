package commands

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/rulemeta"
	"github.com/stretchr/testify/require"
)

func TestListRulesTable(t *testing.T) {
	buf := new(bytes.Buffer)
	// Reset flags
	flagCategory = ""
	flagFormat = "terminal"
	flagDisableRules = nil
	flagRules = ""

	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"list-rules"})
	defer rootCmd.SetArgs(nil)
	defer rootCmd.SetOut(nil)

	err := rootCmd.Execute()
	require.NoError(t, err)

	out := buf.String()
	require.Contains(t, out, "ID")
	require.Contains(t, out, "SEVERITY")
	require.Contains(t, out, "rules loaded")
}

func TestListRulesJSON(t *testing.T) {
	buf := new(bytes.Buffer)
	flagCategory = ""
	flagFormat = "terminal" // will be overridden by --format flag
	flagDisableRules = nil
	flagRules = ""

	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"list-rules", "--format", "json"})
	defer rootCmd.SetArgs(nil)
	defer rootCmd.SetOut(nil)

	err := rootCmd.Execute()
	require.NoError(t, err)

	var rules []rulemeta.Rule
	require.NoError(t, json.Unmarshal(buf.Bytes(), &rules))
	require.GreaterOrEqual(t, len(rules), 70)
	require.NotEmpty(t, rules[0].ID)
	require.NotEmpty(t, rules[0].Severity)
	require.NotEmpty(t, rules[0].Category)
}

func TestListRulesCategoryFilter(t *testing.T) {
	buf := new(bytes.Buffer)
	flagFormat = "terminal"
	flagDisableRules = nil
	flagRules = ""

	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"list-rules", "--category", "prompt-injection"})
	defer rootCmd.SetArgs(nil)
	defer rootCmd.SetOut(nil)

	err := rootCmd.Execute()
	require.NoError(t, err)

	out := buf.String()
	// Every listed rule that starts with a known prefix in the
	// prompt-injection category must land in the right column.
	// The set now includes NLP_* analyzer rules alongside the
	// YAML PROMPT_INJECTION_* rules; both are prompt-injection.
	lines := strings.SplitSeq(out, "\n")
	for line := range lines {
		switch {
		case strings.HasPrefix(line, "PROMPT_INJECTION"),
			strings.HasPrefix(line, "NLP_"):
			require.Contains(t, line, "prompt-injection",
				"rule listed under --category prompt-injection must carry that category in the row: %s", line)
		}
	}
	require.Contains(t, out, "rules loaded")
	// Cross-category rules must NOT leak in. JS_DNS_TXT_EXFIL_001
	// is supply-chain, not prompt-injection -- a regression
	// that surfaces it here means the category filter is broken.
	require.NotContains(t, out, "JS_DNS_TXT_EXFIL_001",
		"supply-chain JS_DNS_TXT_EXFIL_001 must NOT appear under --category prompt-injection")
	require.NotContains(t, out, "GHA_PWN_REQUEST_001",
		"supply-chain GHA_PWN_REQUEST_001 must NOT appear under --category prompt-injection")
}
