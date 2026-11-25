package commands

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

// Errors that already name what is accepted print no usage block, on
// every command. discover, list-rules and status printed it while scan,
// check, audit and explain did not.
func TestSelfExplainingUsageErrorsPrintNoUsageBlock(t *testing.T) {
	// Start from the commands' own settings and restore them afterwards:
	// the fix sets SilenceUsage on the failing command.
	for _, c := range rootCmd.Commands() {
		was := c.SilenceUsage
		t.Cleanup(func() { c.SilenceUsage = was })
	}
	for _, c := range []string{"discover", "list-rules", "status"} {
		cmd, _, err := rootCmd.Find([]string{c})
		require.NoError(t, err)
		cmd.SilenceUsage = false
	}

	cases := [][]string{
		{"discover", "--format", "sarif"},
		{"list-rules", "--format", "sarif"},
		{"explain", "CRED_001", "--format", "md"},
		{"scan", t.TempDir(), "--format", "xml"},
		{"status", "--format", "json"},
		{"list-rules", "--severity", "high"},
		{"check", t.TempDir(), "--rules", t.TempDir()},
	}
	for _, args := range cases {
		resetFlags()
		var out bytes.Buffer
		rootCmd.SetOut(&out)
		rootCmd.SetErr(&out)
		rootCmd.SetArgs(append(args, "--no-update-check"))
		err := rootCmd.Execute()
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		requireUsageError(t, err)
		require.NotContains(t, out.String(), "Usage:", "%v", args)
		require.Contains(t, out.String(), "Error: ", "%v: the error itself is still printed", args)
	}
	resetFlags()
}
