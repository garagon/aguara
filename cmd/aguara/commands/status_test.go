package commands

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestStatusPrintsVersionAndEmbedded asserts the status output
// shape: Version line, embedded snapshot lines, and a Network
// section. Does not exercise the local snapshot path -- that
// depends on $HOME and is covered by intel.Store's own tests.
func TestStatusPrintsVersionAndEmbedded(t *testing.T) {
	resetFlags()
	t.Cleanup(resetFlags)

	stdout, restore := captureStdout(t)
	defer restore()

	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"status", "--no-update-check"})
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
	})

	require.NoError(t, rootCmd.Execute())
	out := stdout()
	require.Contains(t, out, "Aguara")
	require.Contains(t, out, "Threat intel:")
	require.Contains(t, out, "Embedded")
	require.Contains(t, out, "Network:")
	require.Contains(t, out, "Default checks do not use the network")
}

// captureStdout redirects os.Stdout to a temp file for the
// duration of a test, returning a fetcher that drains the file's
// contents and a restore func. Used because the status command
// writes directly to os.Stdout (it does not respect cobra's
// SetOut, like writeCheckJSON in check.go).
func captureStdout(t *testing.T) (func() string, func()) {
	t.Helper()
	orig := os.Stdout
	tmp, err := os.CreateTemp(t.TempDir(), "stdout-*.txt")
	require.NoError(t, err)
	os.Stdout = tmp
	restore := func() {
		os.Stdout = orig
		_ = tmp.Close()
	}
	fetch := func() string {
		_ = tmp.Sync()
		data, err := os.ReadFile(tmp.Name())
		require.NoError(t, err)
		return string(data)
	}
	return fetch, restore
}

// TestStatusReadsLocalSnapshot exercises the local-snapshot
// branch. We point HOME at a tempdir, write a synthetic snapshot
// there, and confirm `aguara status` reports it. Avoids touching
// the user's real ~/.aguara/intel state.
func TestStatusReadsLocalSnapshot(t *testing.T) {
	resetFlags()
	t.Cleanup(resetFlags)

	home := t.TempDir()
	t.Setenv("HOME", home)

	intelDir := filepath.Join(home, ".aguara", "intel")
	require.NoError(t, os.MkdirAll(intelDir, 0o700))
	snap := `{
		"schema_version": 1,
		"generated_at": "2026-05-15T12:00:00Z",
		"records": [
			{"id":"X","ecosystem":"npm","name":"x","versions":["1.0.0"]}
		]
	}`
	require.NoError(t, os.WriteFile(filepath.Join(intelDir, "snapshot.json"), []byte(snap), 0o600))

	stdout, restore := captureStdout(t)
	defer restore()

	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"status", "--no-update-check"})
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
	})

	require.NoError(t, rootCmd.Execute())
	out := stdout()
	require.True(t, strings.Contains(out, "Local:"), "status output must include Local line; got: %s", out)
	require.True(t, strings.Contains(out, "1 records"), "local record count must surface; got: %s", out)
}
