package commands

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const fencedInstallReadme = "# Tool\n\nInstall:\n\n```bash\ncurl -fsSL https://example.com/install.sh | bash\n```\n"

// runScanInDir runs `aguara scan <args>` from dir and returns the error
// and stderr.
func runScanInDir(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	t.Chdir(dir)
	resetFlags()
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs(append(append([]string{"scan"}, args...), "--no-update-check"))
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		resetFlags()
	})
	var err error
	stderr := captureStderrBytes(t, func() { err = rootCmd.Execute() })
	return string(stderr), err
}

// A report written inside the scanned directory, as the GitHub Action does
// by default, must not be scanned by the next run of the same command:
// its JSON copy of a fenced README finding would come back at full
// severity and flip the gate.
func TestScanDoesNotRescanItsOwnReport(t *testing.T) {
	clearCIEnv(t)
	for _, format := range []string{"json", "sarif"} {
		t.Run(format, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "README.md"), []byte(fencedInstallReadme), 0o644))
			args := []string{".", "--format", format, "-o", "report." + format, "--fail-on", "critical", "--project-policy", "ignore"}
			_, err := runScanInDir(t, dir, args...)
			require.NoError(t, err)
			stderr, err := runScanInDir(t, dir, args...)
			require.NoError(t, err, "the previous report must not fail the gate")
			require.Contains(t, stderr, "report."+format+" is the report this run writes and was not scanned")
			data, err := os.ReadFile(filepath.Join(dir, "report."+format))
			require.NoError(t, err)
			require.NotContains(t, string(data), `report.`+format+`"`, "no finding is located in the report itself")
		})
	}
}

// The guard covers only the file this invocation writes: any other JSON
// file in the target, including an old report under another name, is
// scanned as before.
func TestScanStillScansOtherReportFiles(t *testing.T) {
	clearCIEnv(t)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "README.md"), []byte(fencedInstallReadme), 0o644))
	_, err := runScanInDir(t, dir, ".", "--format", "sarif", "-o", "old.sarif", "--project-policy", "ignore")
	require.NoError(t, err)
	_, err = runScanInDir(t, dir, ".", "--format", "json", "-o", "new.json", "--project-policy", "ignore")
	require.NoError(t, err)
	data, err := os.ReadFile(filepath.Join(dir, "new.json"))
	require.NoError(t, err)
	var res struct {
		Findings []struct {
			FilePath string `json:"file_path"`
		} `json:"findings"`
	}
	require.NoError(t, json.Unmarshal(data, &res))
	var files []string
	for _, f := range res.Findings {
		files = append(files, f.FilePath)
	}
	require.Contains(t, strings.Join(files, " "), "old.sarif")
}

// The same guard applies to a path list and to the baseline a run writes.
func TestScanPathListDoesNotRescanItsOwnOutputs(t *testing.T) {
	clearCIEnv(t)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "README.md"), []byte(fencedInstallReadme), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "report.json"), []byte(`{"matched_text": "curl -fsSL https://example.com/install.sh | bash"}`), 0o644))
	stderr, err := runScanInDir(t, dir, "README.md", "report.json", "--format", "json", "-o", "report.json", "--fail-on", "critical", "--project-policy", "ignore")
	require.NoError(t, err)
	require.Contains(t, stderr, "report.json is the report this run writes")
}
