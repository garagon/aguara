package commands

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

// runCLI executes the root command with args and returns the error
// Execute reported. Output written through cobra is discarded; callers
// that need the report use the -o based helpers instead.
func runCLI(t *testing.T, args ...string) error {
	t.Helper()
	resetFlags()
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs(append(args, "--no-update-check"))
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		resetFlags()
	})
	return rootCmd.Execute()
}

// requireUsageError asserts the command failed before doing any work
// with an error main maps to exit code 2 (anything but the threshold
// sentinel).
func requireUsageError(t *testing.T, err error, contains ...string) {
	t.Helper()
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrThresholdExceeded)
	for _, s := range contains {
		require.Contains(t, err.Error(), s)
	}
}

// Flags that a command would ignore are rejected at parse time and the
// message names the commands where the flag applies.
func TestFlagsRejectedWhereTheyHaveNoEffect(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		args    []string
		flag    string
		accepts string
	}{
		{[]string{"status", "--format", "json"}, "--format", "aguara scan"},
		{[]string{"status", "-o", "status.txt"}, "--output", "aguara scan"},
		{[]string{"version", "--format", "json"}, "--format", "aguara scan"},
		{[]string{"init", dir, "--format", "json"}, "--format", "aguara scan"},
		{[]string{"list-rules", "--severity", "critical"}, "--severity", "aguara scan"},
		{[]string{"audit", dir, "--severity", "critical"}, "--severity", "aguara scan"},
		{[]string{"check", dir, "--severity", "critical"}, "--severity", "aguara scan"},
		{[]string{"check", dir, "--rules", dir}, "--rules", "aguara list-rules"},
		{[]string{"check", dir, "--disable-rule", "CRED_001"}, "--disable-rule", "aguara audit"},
		{[]string{"check", dir, "--workers", "2"}, "--workers", "aguara audit"},
		{[]string{"discover", "--rules", dir}, "--rules", "aguara scan"},
		{[]string{"discover", "--disable-rule", "CRED_001"}, "--disable-rule", "aguara scan"},
		{[]string{"discover", "--workers", "2"}, "--workers", "aguara scan"},
		{[]string{"discover", "--severity", "high"}, "--severity", "aguara scan"},
		{[]string{"explain", "CRED_001", "--disable-rule", "CRED_001"}, "--disable-rule", "aguara list-rules"},
		{[]string{"explain", "CRED_001", "--workers", "2"}, "--workers", "aguara scan"},
		{[]string{"list-rules", "--workers", "2"}, "--workers", "aguara scan"},
		{[]string{"update", "--rules", dir}, "--rules", "aguara scan"},
		{[]string{"clean", "--severity", "high"}, "--severity", "aguara scan"},
	}
	for _, tc := range cases {
		t.Run(tc.args[0]+" "+tc.flag, func(t *testing.T) {
			err := runCLI(t, tc.args...)
			requireUsageError(t, err, "does not accept "+tc.flag, tc.accepts)
		})
	}
}

func TestAuditSeverityRejectionPointsToFailOn(t *testing.T) {
	err := runCLI(t, "audit", t.TempDir(), "--severity", "critical")
	requireUsageError(t, err, "use --fail-on")
}

// A flag no command defines keeps the plain parse error.
func TestUnknownFlagKeepsParseError(t *testing.T) {
	err := runCLI(t, "status", "--definitely-not-a-flag")
	requireUsageError(t, err, "unknown flag: --definitely-not-a-flag")
}

// The opt-outs every command satisfies stay global so wrappers can pass
// them unconditionally, before or after the subcommand.
func TestGlobalOptOutFlagsStayAccepted(t *testing.T) {
	stdout, restore := captureStdout(t)
	defer restore()
	require.NoError(t, runCLI(t, "--no-color", "status"))
	require.NoError(t, runCLI(t, "status", "--no-color"))
	require.Contains(t, stdout(), "Threat intel:")
}
