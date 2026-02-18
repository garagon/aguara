package commands

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

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

	var rules []ruleInfo
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
	lines := strings.SplitSeq(out, "\n")
	for line := range lines {
		if strings.HasPrefix(line, "PROMPT_INJECTION") {
			require.Contains(t, line, "prompt-injection")
		}
	}
	require.Contains(t, out, "rules loaded")
	require.NotContains(t, out, "EXFIL_")
}
