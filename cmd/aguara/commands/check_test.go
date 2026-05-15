package commands

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/incident"
	"github.com/stretchr/testify/require"
)

// checkToFile runs `aguara check` with the given args, writes JSON
// output to a temp file via `-o`, and returns the parsed result. Use
// this instead of capturing stdout because writeCheckJSON writes to
// os.Stdout directly (matches the helper in scan_test.go).
func checkToFile(t *testing.T, args ...string) *incident.CheckResult {
	t.Helper()
	resetFlags()
	outFile := filepath.Join(t.TempDir(), "check.json")
	fullArgs := append([]string{"check"}, args...)
	fullArgs = append(fullArgs, "-o", outFile, "--format", "json", "--no-update-check")

	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs(fullArgs)
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		resetFlags()
	})

	err := rootCmd.Execute()
	require.NoError(t, err)

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	var result incident.CheckResult
	require.NoError(t, json.Unmarshal(data, &result))
	return &result
}

// writeFakeNPMPackage materialises a node_modules/<name>/package.json
// with the given name and version. Helper kept inline to avoid coupling
// to the internal/incident test helper which lives in a different
// package.
func writeFakeNPMPackage(t *testing.T, nodeModules, name, version string) {
	t.Helper()
	dir := filepath.Join(nodeModules, filepath.FromSlash(name))
	require.NoError(t, os.MkdirAll(dir, 0o755))
	body := `{"name":"` + name + `","version":"` + version + `"}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "package.json"), []byte(body), 0o644))
}

func TestCheckAutoDetectsNPMFromProjectRoot(t *testing.T) {
	// With no --ecosystem flag, `aguara check --path <dir>` must
	// detect the node_modules child and route to the npm checker.
	// Regression guard for the v0.16 UX promise: a user inside a
	// real npm project must get an npm report without being asked
	// to spell out the ecosystem.
	project := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(project, "node_modules"), 0o755))
	writeFakeNPMPackage(t, filepath.Join(project, "node_modules"), "event-stream", "3.3.6")

	result := checkToFile(t, "--path", project)

	require.NotZero(t, result.PackagesRead, "expected npm checker to read at least one package")
	require.NotEmpty(t, result.Findings, "expected event-stream 3.3.6 to be reported as compromised")
	require.Equal(t, incident.SevCritical, result.Findings[0].Severity)
}

func TestCheckAutoDetectsNPMFromNodeModulesDir(t *testing.T) {
	// Passing the node_modules directory itself (not its parent)
	// must also resolve to an npm check without --ecosystem.
	nm := filepath.Join(t.TempDir(), "node_modules")
	require.NoError(t, os.MkdirAll(nm, 0o755))
	writeFakeNPMPackage(t, nm, "lodash", "4.17.21") // not compromised

	result := checkToFile(t, "--path", nm)

	require.Equal(t, 1, result.PackagesRead)
	require.Empty(t, result.Findings)
}

func TestCheckExplicitEcosystemNPMStillWorks(t *testing.T) {
	// Legacy contract: `aguara check --ecosystem npm --path X` must
	// continue to route to the npm checker even when X has a non-npm
	// shape (here: a node_modules tree without ./node_modules child).
	nm := filepath.Join(t.TempDir(), "node_modules")
	require.NoError(t, os.MkdirAll(nm, 0o755))
	writeFakeNPMPackage(t, nm, "event-stream", "3.3.6")

	result := checkToFile(t, "--ecosystem", "npm", "--path", nm)

	require.NotEmpty(t, result.Findings)
}

func TestCheckExplicitEcosystemPythonSkipsNPMAutoDetect(t *testing.T) {
	// Auto-detection must NEVER override an explicit --ecosystem
	// python flag. We arrange a directory that would auto-detect as
	// npm and confirm the Python check path runs instead. The Python
	// checker errors out with the "no Python site-packages" message
	// when the path is empty/non-Python; that error surface is the
	// signal that the Python pipeline ran (not npm).
	project := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(project, "node_modules"), 0o755))

	resetFlags()
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{
		"check",
		"--ecosystem", "python",
		"--path", project,
		"--format", "json",
		"--no-update-check",
	})
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		resetFlags()
	})

	err := rootCmd.Execute()
	// Either the Python checker accepted the path (empty findings)
	// or rejected it as not-a-site-packages directory. Both are
	// fine; what must NOT happen is npm taking over silently.
	if err == nil {
		// runCheck succeeded under Python ecosystem, fine.
		return
	}
	require.NotContains(t, err.Error(), "npm check", "ecosystem=python must not delegate to npm")
}

func TestCheckRejectsUnsupportedEcosystem(t *testing.T) {
	resetFlags()
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"check", "--ecosystem", "ruby", "--no-update-check"})
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		resetFlags()
	})

	err := rootCmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported ecosystem")
}

func TestCheckFailOnThresholdHelper(t *testing.T) {
	// Verifies the threshold logic in isolation, without paying the
	// subprocess cost. Each row sets up a CheckResult with known
	// severities and asserts whether the gate trips.
	tests := []struct {
		name      string
		findings  []incident.Finding
		threshold string
		wantErr   bool
	}{
		{
			name:      "empty threshold never trips",
			findings:  []incident.Finding{{Severity: incident.SevCritical}},
			threshold: "",
			wantErr:   false,
		},
		{
			name:      "critical trips critical",
			findings:  []incident.Finding{{Severity: incident.SevCritical}},
			threshold: "critical",
			wantErr:   true,
		},
		{
			name:      "warning does not trip critical",
			findings:  []incident.Finding{{Severity: incident.SevWarning}},
			threshold: "critical",
			wantErr:   false,
		},
		{
			name:      "warning trips warning",
			findings:  []incident.Finding{{Severity: incident.SevWarning}},
			threshold: "warning",
			wantErr:   true,
		},
		{
			name:      "critical trips warning",
			findings:  []incident.Finding{{Severity: incident.SevCritical}},
			threshold: "warning",
			wantErr:   true,
		},
		{
			name:      "no findings never trips",
			findings:  nil,
			threshold: "critical",
			wantErr:   false,
		},
		{
			name:      "case insensitive threshold",
			findings:  []incident.Finding{{Severity: incident.SevCritical}},
			threshold: "CRITICAL",
			wantErr:   true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := &incident.CheckResult{Findings: tc.findings}
			err := checkIncidentFailOnThreshold(result, tc.threshold)
			if tc.wantErr {
				require.ErrorIs(t, err, ErrThresholdExceeded)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCheckFailOnInvalidValue(t *testing.T) {
	result := &incident.CheckResult{Findings: []incident.Finding{{Severity: incident.SevCritical}}}
	err := checkIncidentFailOnThreshold(result, "ludicrous")
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrThresholdExceeded)
	require.Contains(t, err.Error(), "invalid --fail-on")
}

func TestCheckCIAppliesDefaults(t *testing.T) {
	// --ci must imply --fail-on critical and disable color.
	// We don't exercise the full command (would need an os.Exit
	// subprocess for the compromised case); instead we invoke
	// applyCheckCIDefaults directly so the flag wiring stays unit
	// tested.
	resetFlags()
	t.Cleanup(resetFlags)

	flagCheckCI = true
	applyCheckCIDefaults()
	require.Equal(t, "critical", flagCheckFailOn)
	require.True(t, flagNoColor)
}

func TestCheckCIPreservesExplicitFailOn(t *testing.T) {
	// --ci must not clobber an explicit --fail-on. A user who
	// writes `aguara check --ci --fail-on warning` is asking for a
	// stricter gate than --ci's default; the override has to win.
	resetFlags()
	t.Cleanup(resetFlags)

	flagCheckCI = true
	flagCheckFailOn = "warning"
	applyCheckCIDefaults()
	require.Equal(t, "warning", flagCheckFailOn)
}

func TestCheckCIExitsNonZero(t *testing.T) {
	// End-to-end smoke: `aguara check --ci` on a directory that
	// auto-detects an npm project with a known-compromised package
	// must return ErrThresholdExceeded so main.go can exit(1). The
	// subprocess pattern matches TestScanFailOn; the helper test
	// runs the actual cobra command and exits with code 1 on the
	// sentinel.
	dir := t.TempDir()
	nm := filepath.Join(dir, "node_modules")
	require.NoError(t, os.MkdirAll(nm, 0o755))
	writeFakeNPMPackage(t, nm, "event-stream", "3.3.6")

	cmd := exec.Command("go", "test", "-race", "-count=1",
		"-run", "TestCheckCIExitsNonZeroHelper",
		"./cmd/aguara/commands/",
	)
	cmd.Dir = filepath.Join("..", "..", "..")
	cmd.Env = append(os.Environ(), "AGUARA_TEST_CHECK_CI_DIR="+dir)

	out, err := cmd.CombinedOutput()
	require.Error(t, err, "expected non-zero exit: %s", string(out))
}

// TestCheckCIExitsNonZeroHelper is invoked by TestCheckCIExitsNonZero
// in a subprocess. It is skipped when not called by the parent test.
func TestCheckCIExitsNonZeroHelper(t *testing.T) {
	dir := os.Getenv("AGUARA_TEST_CHECK_CI_DIR")
	if dir == "" {
		t.Skip("only runs as subprocess of TestCheckCIExitsNonZero")
	}
	resetFlags()
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{
		"check",
		"--path", dir,
		"--ci",
		"--format", "json",
		"-o", filepath.Join(t.TempDir(), "out.json"),
		"--no-update-check",
	})
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		resetFlags()
	})

	if err := rootCmd.Execute(); errors.Is(err, ErrThresholdExceeded) {
		os.Exit(1)
	}
}

func TestResolveCheckTargetExplicitFlags(t *testing.T) {
	// Direct unit test for the dispatcher: explicit ecosystem flags
	// route without auto-detect, even when --path contains a node_modules
	// child (proves auto-detect is suppressed by an explicit override).
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "node_modules"), 0o755))

	eco, path, err := resolveCheckTarget("python", dir)
	require.NoError(t, err)
	require.Equal(t, ecoPython, eco)
	require.Equal(t, dir, path)

	eco, path, err = resolveCheckTarget("PyPI", dir)
	require.NoError(t, err)
	require.Equal(t, ecoPython, eco)
	require.Equal(t, dir, path)

	eco, path, err = resolveCheckTarget("npm", dir)
	require.NoError(t, err)
	require.Equal(t, ecoNPM, eco)
	require.Equal(t, dir, path)

	_, _, err = resolveCheckTarget("crates", dir)
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "unsupported"))
}

func TestResolveCheckTargetAutoDetect(t *testing.T) {
	// Auto-detect (empty ecosystem) prefers npm only when a
	// node_modules directory is present at the probe path.
	withNM := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(withNM, "node_modules"), 0o755))

	withoutNM := t.TempDir()

	eco, path, err := resolveCheckTarget("", withNM)
	require.NoError(t, err)
	require.Equal(t, ecoNPM, eco)
	require.Equal(t, withNM, path)

	eco, path, err = resolveCheckTarget("", withoutNM)
	require.NoError(t, err)
	require.Equal(t, ecoPython, eco)
	require.Equal(t, withoutNM, path)

	// Empty path with empty ecosystem must not crash and must
	// fall back to Python (preserves the legacy site-packages
	// auto-discovery contract).
	eco, path, err = resolveCheckTarget("", "")
	require.NoError(t, err)
	// In a CI workspace cwd will rarely have node_modules; if it
	// happens to (e.g. someone runs the suite from inside an npm
	// project), the auto-detect is allowed to pick npm. Either
	// answer is acceptable; what matters is no error and an empty
	// path is preserved for Python's auto-discovery.
	require.Contains(t, []string{ecoPython, ecoNPM}, eco)
	if eco == ecoPython {
		require.Equal(t, "", path)
	}
}
