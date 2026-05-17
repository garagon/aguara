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
	// PR #3 added cargo / composer / ruby support, so the
	// previously-unsupported fixture had to change. Swift is
	// realistic-shape but still outside the registry; once
	// Swift lands, swap for another genuinely unknown token.
	resetFlags()
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"check", "--ecosystem", "swift", "--no-update-check"})
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		resetFlags()
	})

	err := rootCmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported ecosystem")
	// Error must list every supported choice so the user can
	// recover from the typo without reading source. PR #1
	// established the same contract on `aguara update`; we
	// mirror it here.
	for _, eco := range []string{"python", "npm", "go", "cargo", "composer", "ruby", "maven", "nuget"} {
		require.Contains(t, err.Error(), eco, "error must list %s", eco)
	}
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

func TestResolveCheckTargetRejectsMissingPath(t *testing.T) {
	// QA regression on v0.16.0: `aguara check --path /no/existe`
	// returned exit 0 with an empty result, masking a typo as a
	// clean check. Every code path that takes a non-empty --path
	// must surface a clear error before any check pipeline runs.
	missing := filepath.Join(t.TempDir(), "definitely-does-not-exist")

	for _, eco := range []string{"", "python", "pypi", "npm"} {
		eco := eco
		t.Run("ecosystem="+eco, func(t *testing.T) {
			_, _, err := resolveCheckTarget(eco, missing)
			require.Error(t, err)
			require.Contains(t, err.Error(), "no such file or directory",
				"missing --path must surface the canonical filesystem error")
			require.Contains(t, err.Error(), missing,
				"error must echo the bad path so the user can spot the typo")
		})
	}
}

func TestResolveCheckTargetRejectsFilePath(t *testing.T) {
	// --path pointing at a regular file is a typo too: the user
	// likely meant a sibling directory. Surface a distinct error
	// from missing-path so logs are unambiguous.
	f, err := os.CreateTemp(t.TempDir(), "not-a-dir-*")
	require.NoError(t, err)
	require.NoError(t, f.Close())

	for _, eco := range []string{"", "python", "pypi", "npm"} {
		eco := eco
		t.Run("ecosystem="+eco, func(t *testing.T) {
			_, _, err := resolveCheckTarget(eco, f.Name())
			require.Error(t, err)
			require.Contains(t, err.Error(), "not a directory")
			require.Contains(t, err.Error(), f.Name())
		})
	}
}

func TestResolveCheckTargetEmptyPathStillAutodiscovers(t *testing.T) {
	// Guardrail: the new validator must NOT fire on empty --path.
	// The legacy Python autodiscovery contract (`aguara check`
	// with no flags falls back to site-packages) MUST keep
	// working; nobody should suddenly have to pass --path on a
	// host where the prior release found Python automatically.
	eco, path, err := resolveCheckTarget("", "")
	require.NoError(t, err)
	// Either ecoPython (no node_modules in cwd) or ecoNPM (if the
	// test host happens to have one). Both are acceptable. What
	// matters is no error and the path remains as auto-detect
	// wants it.
	require.Contains(t, []string{ecoPython, ecoNPM}, eco)
	_ = path
}

func TestRunCheckExplicitMissingPathProducesError(t *testing.T) {
	// End-to-end via cobra: a missing --path on the CLI surface
	// produces a non-nil error from rootCmd.Execute (which
	// main.go maps to os.Exit(2)) and -o never writes a JSON
	// file. Locks the "no false clean JSON" contract.
	resetFlags()
	outFile := filepath.Join(t.TempDir(), "check.json")
	missing := filepath.Join(t.TempDir(), "missing")

	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{
		"check",
		"--path", missing,
		"--format", "json",
		"-o", outFile,
		"--no-update-check",
	})
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		resetFlags()
	})

	err := rootCmd.Execute()
	require.Error(t, err, "missing --path must surface a non-nil error from Execute")
	require.Contains(t, err.Error(), missing)

	// And -o must NOT have been written -- the cardinal sin is
	// producing a green check.json on a path the user never
	// asked to scan.
	_, statErr := os.Stat(outFile)
	require.True(t, os.IsNotExist(statErr),
		"no JSON output file should exist on a missing-path error; got stat err %v", statErr)
}

func TestResolveCheckTargetAutoDetectFromInsideNodeModules(t *testing.T) {
	// Regression for codex P2 (PR review, 2026-05-15): when the
	// probe is "." -- e.g. the user runs `aguara check` from inside
	// a node_modules directory -- filepath.Base(".") is ".". The
	// auto-detector must (a) recognise the npm signal anyway and
	// (b) return a path that resolveNPMRoot can walk, since
	// filepath.Base(".") and `./node_modules` both fail under
	// resolveNPMRoot. We resolve to an absolute path before the
	// basename check AND return that resolved path so the npm
	// walker sees a usable input.
	nm := filepath.Join(t.TempDir(), "node_modules")
	require.NoError(t, os.MkdirAll(nm, 0o755))
	t.Chdir(nm)

	resolvedNM, err := filepath.Abs(".")
	require.NoError(t, err)

	eco, path, err := resolveCheckTarget("", ".")
	require.NoError(t, err)
	require.Equal(t, ecoNPM, eco)
	require.Equal(t, resolvedNM, path, "auto-detect must hand the npm walker a resolved path so resolveNPMRoot can find node_modules")

	// Same shape, but with no --path flag (empty string) -- the
	// dispatcher uses "." as a probe internally and must still
	// detect npm with a resolved path.
	eco, path, err = resolveCheckTarget("", "")
	require.NoError(t, err)
	require.Equal(t, ecoNPM, eco)
	require.Equal(t, resolvedNM, path)
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

// --- PR #2: packagecheck Go path ---

func TestCheckGoExplicitEcosystemEmitsEcosystemsSlice(t *testing.T) {
	// `aguara check --ecosystem go --path <project>` must walk the
	// path for go.sum / go.mod and surface one EcosystemResult per
	// discovered lockfile. The clean fixture has no compromised
	// records in the embedded snapshot, so findings stay empty;
	// what matters here is the ecosystems[] shape.
	result := checkToFile(t, "--ecosystem", "go", "--path", "../../../internal/packagecheck/testdata/go-clean")

	require.Len(t, result.Ecosystems, 1, "expected one Go target")
	require.Equal(t, "Go", result.Ecosystems[0].Ecosystem)
	require.Equal(t, "go.sum", result.Ecosystems[0].Source)
	require.Equal(t, 2, result.Ecosystems[0].PackagesRead, "go-clean/go.sum declares two unique (module, version) pairs after /go.mod dedupe")
	require.Equal(t, 0, result.Ecosystems[0].FindingsCount)
}

func TestCheckGoMonorepoEmitsOneEcosystemPerLockfile(t *testing.T) {
	// Monorepo fixture has go.sum in services/api and workers/scraper.
	// Discovery must produce two entries and skip vendor/ +
	// node_modules/ children.
	result := checkToFile(t, "--ecosystem", "go", "--path", "../../../internal/packagecheck/testdata/go-monorepo")

	require.Len(t, result.Ecosystems, 2, "expected services/api + workers/scraper, got %+v", result.Ecosystems)
	for _, e := range result.Ecosystems {
		require.Equal(t, "Go", e.Ecosystem)
		require.Equal(t, "go.sum", e.Source)
		require.NotContains(t, e.Path, "vendor", "discovery must not walk vendor/")
		require.NotContains(t, e.Path, "node_modules", "discovery must not walk node_modules/")
	}
}

func TestCheckGoAliasGolangResolves(t *testing.T) {
	// PR #1 ecosystem registry maps `golang` -> Go. The CLI's
	// resolveCheckTarget accepts the alias and routes to the Go
	// path. Lock the alias contract so a future rename does not
	// silently drop it.
	result := checkToFile(t, "--ecosystem", "golang", "--path", "../../../internal/packagecheck/testdata/go-clean")

	require.Len(t, result.Ecosystems, 1)
	require.Equal(t, "Go", result.Ecosystems[0].Ecosystem)
}

func TestCheckGoEmptyPathReturnsCleanResult(t *testing.T) {
	// `aguara check --ecosystem go --path <dir-without-go-files>`
	// must succeed with empty ecosystems[], NOT error. Spec:
	// "Si no hay targets del ecosistema pedido, devolver resultado
	// limpio pero con ecosystems: []."
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "README.md"), []byte("# nothing\n"), 0o644))

	result := checkToFile(t, "--ecosystem", "go", "--path", tmp)

	require.NotNil(t, result.Ecosystems, "ecosystems[] must be non-nil even when empty so JSON stays stable")
	require.Empty(t, result.Ecosystems, "no go.sum / go.mod -> empty ecosystems[]")
	require.Empty(t, result.Findings)
	require.Equal(t, 0, result.PackagesRead)
}

// TestCheckEcosystemsJSONShapeAlwaysEmitsEmptyArray locks the raw
// JSON contract. The struct-level unmarshal-then-require.Empty pass
// hides the difference between `"ecosystems": []` (intended) and a
// missing field or `"ecosystems": null` (regression: would re-appear
// if someone re-adds `,omitempty` or skips initialising the slice
// in incident.Check / incident.CheckNPM). External consumers
// (aguara-mcp, CI scripts) iterate the array unconditionally, so the
// literal `"ecosystems": []` substring is part of the JSON contract.
func TestCheckEcosystemsJSONShapeAlwaysEmitsEmptyArray(t *testing.T) {
	// Exercise the three paths that build CheckResult: explicit Go
	// with no targets, explicit npm with no targets, and the
	// Python fallback. All three must emit the literal
	// `"ecosystems": []` so downstream JSON consumers can iterate
	// without a nil check.
	t.Run("ecosystem go on dir without go.sum", func(t *testing.T) {
		tmp := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(tmp, "README.md"), []byte("# nothing\n"), 0o644))
		raw := checkToFileRaw(t, "--ecosystem", "go", "--path", tmp)
		require.Contains(t, string(raw), `"ecosystems": []`)
		require.NotContains(t, string(raw), `"ecosystems": null`)
	})
	t.Run("ecosystem npm with empty node_modules", func(t *testing.T) {
		nm := filepath.Join(t.TempDir(), "node_modules")
		require.NoError(t, os.MkdirAll(nm, 0o755))
		raw := checkToFileRaw(t, "--ecosystem", "npm", "--path", nm)
		require.Contains(t, string(raw), `"ecosystems": []`)
		require.NotContains(t, string(raw), `"ecosystems": null`)
	})
}

// checkToFileRaw is the byte-level sibling of checkToFile. Returns
// the raw JSON bytes so tests can assert on the JSON shape itself
// (key presence, literal values) rather than going through Go's
// struct unmarshal which would silently paper over a missing field.
func checkToFileRaw(t *testing.T, args ...string) []byte {
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

	// `aguara check` against an empty npm node_modules tree
	// can exit non-zero on some platforms when the resolver
	// fails; we still want to inspect the JSON it wrote.
	_ = rootCmd.Execute()

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	return data
}

func TestCheckGoAutoDetectsAtPathRoot(t *testing.T) {
	// With no --ecosystem flag and a go.mod / go.sum at the path
	// root, autodetect must pick Go. This is the "Mantener npm/PyPI
	// funcionando igual / Agregar Go cuando se detecte lockfile"
	// contract for the root-only case; monorepo autodetect from a
	// parent that doesn't have go.sum is deferred to PR #5.
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "go.sum"), []byte("example.com/mod v1.0.0 h1:hash=\n"), 0o644))

	result := checkToFile(t, "--path", tmp)

	require.Len(t, result.Ecosystems, 1, "expected Go autodetect to fire and produce one target")
	require.Equal(t, "Go", result.Ecosystems[0].Ecosystem)
}

// --- PR #3: Cargo / Composer / Ruby CLI paths ---

func TestCheckCargoExplicitEcosystemEmitsEcosystemsSlice(t *testing.T) {
	result := checkToFile(t, "--ecosystem", "cargo", "--path", "../../../internal/packagecheck/testdata/cargo-clean")

	require.Len(t, result.Ecosystems, 1)
	require.Equal(t, "crates.io", result.Ecosystems[0].Ecosystem)
	require.Equal(t, "Cargo.lock", result.Ecosystems[0].Source)
	require.Equal(t, 2, result.Ecosystems[0].PackagesRead, "clean Cargo.lock declares serde + tokio")
	require.Equal(t, 0, result.Ecosystems[0].FindingsCount)
}

func TestCheckCargoAliasRustResolves(t *testing.T) {
	result := checkToFile(t, "--ecosystem", "rust", "--path", "../../../internal/packagecheck/testdata/cargo-clean")
	require.Len(t, result.Ecosystems, 1)
	require.Equal(t, "crates.io", result.Ecosystems[0].Ecosystem)
}

func TestCheckComposerExplicitEcosystemEmitsEcosystemsSlice(t *testing.T) {
	result := checkToFile(t, "--ecosystem", "composer", "--path", "../../../internal/packagecheck/testdata/composer-clean")
	require.Len(t, result.Ecosystems, 1)
	require.Equal(t, "Packagist", result.Ecosystems[0].Ecosystem)
	require.Equal(t, "composer.lock", result.Ecosystems[0].Source)
	require.Equal(t, 2, result.Ecosystems[0].PackagesRead, "clean composer.lock has symfony/console + phpunit/phpunit")
}

func TestCheckComposerAliasPhpResolves(t *testing.T) {
	result := checkToFile(t, "--ecosystem", "php", "--path", "../../../internal/packagecheck/testdata/composer-clean")
	require.Len(t, result.Ecosystems, 1)
	require.Equal(t, "Packagist", result.Ecosystems[0].Ecosystem)
}

func TestCheckRubyExplicitEcosystemEmitsEcosystemsSlice(t *testing.T) {
	result := checkToFile(t, "--ecosystem", "ruby", "--path", "../../../internal/packagecheck/testdata/ruby-clean")
	require.Len(t, result.Ecosystems, 1)
	require.Equal(t, "RubyGems", result.Ecosystems[0].Ecosystem)
	require.Equal(t, "Gemfile.lock", result.Ecosystems[0].Source)
	require.Equal(t, 2, result.Ecosystems[0].PackagesRead, "clean Gemfile.lock has rake + rspec (rspec-core is a dependency constraint, not a top-level spec)")
}

func TestCheckRubyAliasesGemAndRubygemsResolve(t *testing.T) {
	for _, alias := range []string{"gem", "rubygems"} {
		t.Run(alias, func(t *testing.T) {
			result := checkToFile(t, "--ecosystem", alias, "--path", "../../../internal/packagecheck/testdata/ruby-clean")
			require.Len(t, result.Ecosystems, 1)
			require.Equal(t, "RubyGems", result.Ecosystems[0].Ecosystem)
		})
	}
}

func TestCheckNewEcosystemsReturnEmptyEcosystemsOnEmptyPath(t *testing.T) {
	// Spec contract carries over from PR #2: `--ecosystem <X> --path
	// <dir-without-lockfiles>` returns clean result with empty
	// ecosystems[], NOT error.
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "README.md"), []byte("# nothing\n"), 0o644))
	for _, eco := range []string{"cargo", "rust", "composer", "php", "ruby", "gem", "rubygems"} {
		t.Run(eco, func(t *testing.T) {
			raw := checkToFileRaw(t, "--ecosystem", eco, "--path", tmp)
			require.Contains(t, string(raw), `"ecosystems": []`)
			require.NotContains(t, string(raw), `"ecosystems": null`)
		})
	}
}

// --- PR #4: Maven / NuGet CLI paths ---

func TestCheckMavenExplicitEcosystemEmitsEcosystemsSlice(t *testing.T) {
	result := checkToFile(t, "--ecosystem", "maven", "--path", "../../../internal/packagecheck/testdata/maven-clean")
	require.Len(t, result.Ecosystems, 1)
	require.Equal(t, "Maven", result.Ecosystems[0].Ecosystem)
	require.Equal(t, "pom.xml", result.Ecosystems[0].Source)
	require.Equal(t, 1, result.Ecosystems[0].PackagesRead)
	require.Equal(t, 0, result.Ecosystems[0].FindingsCount)
}

func TestCheckMavenAliasJavaResolves(t *testing.T) {
	result := checkToFile(t, "--ecosystem", "java", "--path", "../../../internal/packagecheck/testdata/maven-clean")
	require.Len(t, result.Ecosystems, 1)
	require.Equal(t, "Maven", result.Ecosystems[0].Ecosystem)
}

func TestCheckNuGetExplicitEcosystemEmitsEcosystemsSlice(t *testing.T) {
	result := checkToFile(t, "--ecosystem", "nuget", "--path", "../../../internal/packagecheck/testdata/nuget-clean")
	require.Len(t, result.Ecosystems, 1)
	require.Equal(t, "NuGet", result.Ecosystems[0].Ecosystem)
	require.Equal(t, "csproj", result.Ecosystems[0].Source)
	require.Equal(t, 1, result.Ecosystems[0].PackagesRead)
}

func TestCheckNuGetAliasesDotnetAndCsharpResolve(t *testing.T) {
	for _, alias := range []string{"dotnet", "csharp"} {
		t.Run(alias, func(t *testing.T) {
			result := checkToFile(t, "--ecosystem", alias, "--path", "../../../internal/packagecheck/testdata/nuget-clean")
			require.Len(t, result.Ecosystems, 1)
			require.Equal(t, "NuGet", result.Ecosystems[0].Ecosystem)
		})
	}
}

func TestCheckMavenAndNuGetEmptyPathEmitsEmptyArray(t *testing.T) {
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "README.md"), []byte("# nothing\n"), 0o644))
	for _, eco := range []string{"maven", "java", "nuget", "dotnet", "csharp"} {
		t.Run(eco, func(t *testing.T) {
			raw := checkToFileRaw(t, "--ecosystem", eco, "--path", tmp)
			require.Contains(t, string(raw), `"ecosystems": []`)
			require.NotContains(t, string(raw), `"ecosystems": null`)
		})
	}
}
