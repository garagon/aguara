package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// --fail-on-empty turns a scan of zero files into a failure (exit 2, not
// the findings exit 1) while still writing the report that says so.
func TestFailOnEmptyFailsAZeroFileScan(t *testing.T) {
	empty := t.TempDir()
	out := filepath.Join(t.TempDir(), "report.json")
	err := runCLI(t, "scan", empty, "--fail-on-empty", "--format", "json", "-o", out)
	requireUsageError(t, err, "no files were scanned", "--fail-on-empty")

	data, readErr := os.ReadFile(out)
	require.NoError(t, readErr, "the report is still written")
	var result struct {
		Coverage struct {
			FilesScanned int `json:"files_scanned"`
		} `json:"coverage"`
	}
	require.NoError(t, json.Unmarshal(data, &result))
	require.Zero(t, result.Coverage.FilesScanned)
}

func TestFailOnEmptyPassesWhenFilesWereScanned(t *testing.T) {
	dir := projectWith(t, map[string]string{"notes.md": "# notes\n"})
	require.NoError(t, runCLI(t, "scan", dir, "--fail-on-empty", "-o", filepath.Join(t.TempDir(), "r")))
}

func TestFailOnEmptyAppliesToAnEmptyChangeSet(t *testing.T) {
	repo := commitRepo(t, map[string]string{"a.md": "# a\n"})
	err := runCLI(t, "scan", repo, "--changed", "--fail-on-empty", "-o", filepath.Join(t.TempDir(), "r"))
	requireUsageError(t, err, "no files were scanned")
}

// An empty scan never establishes a baseline under --fail-on-empty.
func TestFailOnEmptyDoesNotWriteABaseline(t *testing.T) {
	base := filepath.Join(t.TempDir(), "baseline.json")
	err := runCLI(t, "scan", t.TempDir(), "--fail-on-empty", "--write-baseline", base, "-o", filepath.Join(t.TempDir(), "r"))
	requireUsageError(t, err, "no files were scanned")
	_, statErr := os.Stat(base)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

// With no MCP configurations, --auto still writes its report in the
// selected format and --fail-on-empty fails the run.
func TestAutoScanWithoutConfigsHonorsFormatAndFailOnEmpty(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Chdir(t.TempDir())

	out := filepath.Join(t.TempDir(), "auto.json")
	require.NoError(t, runCLI(t, "scan", "--auto", "--format", "json", "-o", out))
	data, err := os.ReadFile(out)
	require.NoError(t, err)
	require.Contains(t, string(data), `"scope": "auto"`)
	require.Contains(t, string(data), `"files_scanned": 0`)

	err = runCLI(t, "scan", "--auto", "--fail-on-empty", "-o", filepath.Join(t.TempDir(), "r"))
	requireUsageError(t, err, "no files were scanned", "no MCP client configurations were found")
	require.NotContains(t, err.Error(), "path", "--auto takes no path to check")
}
