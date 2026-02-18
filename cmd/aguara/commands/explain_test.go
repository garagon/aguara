package commands

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExplainKnownRule(t *testing.T) {
	buf := new(bytes.Buffer)
	flagFormat = "terminal"
	flagNoColor = true
	flagRules = ""

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
	flagFormat = "terminal"
	flagRules = ""

	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"explain", "PROMPT_INJECTION_001", "--format", "json"})
	defer rootCmd.SetArgs(nil)
	defer rootCmd.SetOut(nil)

	err := rootCmd.Execute()
	require.NoError(t, err)

	var info explainInfo
	require.NoError(t, json.Unmarshal(buf.Bytes(), &info))
	require.Equal(t, "PROMPT_INJECTION_001", info.ID)
	require.Equal(t, "CRITICAL", info.Severity)
	require.Equal(t, "prompt-injection", info.Category)
	require.NotEmpty(t, info.Patterns)
	require.NotEmpty(t, info.TruePositives)
}

func TestExplainNotFound(t *testing.T) {
	buf := new(bytes.Buffer)
	flagFormat = "terminal"
	flagRules = ""

	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"explain", "NONEXISTENT_999"})
	defer rootCmd.SetArgs(nil)
	defer rootCmd.SetOut(nil)
	defer rootCmd.SetErr(nil)

	err := rootCmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
}
