package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type preCommitHook struct {
	ID            string   `yaml:"id"`
	Entry         string   `yaml:"entry"`
	Args          []string `yaml:"args"`
	Language      string   `yaml:"language"`
	Types         []string `yaml:"types"`
	RequireSerial bool     `yaml:"require_serial"`
}

func loadPreCommitHooks(t *testing.T) []preCommitHook {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", ".pre-commit-hooks.yaml"))
	require.NoError(t, err)
	var hooks []preCommitHook
	require.NoError(t, yaml.Unmarshal(data, &hooks))
	require.Len(t, hooks, 2)
	return hooks
}

// pre-commit appends the file names after the hook's entry and args. The
// args end with "--", so a file whose name starts with dashes is never read
// as a flag, and a file named "-" is a file, not standard input.
func TestPreCommitHooksEndOptionsBeforeFileNames(t *testing.T) {
	clearCIEnv(t)
	dir := t.TempDir()
	for name, content := range map[string]string{
		"--fail-on=low.md": injectionPayload,
		"-":                injectionPayload,
		"-v.md":            "# fine\n",
		"README.md":        "# fine\n",
	} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644))
	}
	files := []string{"--fail-on=low.md", "-", "-v.md", "README.md"}
	for _, hook := range loadPreCommitHooks(t) {
		t.Run(hook.ID, func(t *testing.T) {
			require.Equal(t, "--", hook.Args[len(hook.Args)-1], "args must end option parsing")
			require.NotContains(t, strings.Fields(hook.Entry), "--", "user args must still be parsed as flags")
			require.True(t, hook.RequireSerial)
			fields := strings.Fields(hook.Entry)
			require.Equal(t, []string{"aguara", "scan"}, fields[:2])
			// What pre-commit runs: entry, args, then the file names.
			args := append(append(append([]string{}, fields[2:]...), hook.Args...), files...)
			t.Chdir(dir)
			res, _, err := runScanCLI(t, nil, args...)
			require.ErrorIs(t, err, ErrThresholdExceeded, "the flag-like file is scanned and its injection found")
			require.Equal(t, 4, res.FilesScanned)
			require.Contains(t, res.keys(), "--fail-on=low.md:1:PROMPT_INJECTION_001")
		})
	}
}

// Without "--", the same file name would have been taken as a flag.
func TestFlagLikeFileNameNeedsDoubleDash(t *testing.T) {
	clearCIEnv(t)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "--fail-on=low.md"), []byte("# x\n"), 0o644))
	t.Chdir(dir)
	_, _, err := runScanCLI(t, nil, "--root", ".", "README.md", "--fail-on=low.md")
	require.Error(t, err)
	res, _, err := runScanCLI(t, nil, "--root", ".", "--", "--fail-on=low.md")
	require.NoError(t, err)
	require.Equal(t, 1, res.FilesScanned)
}
