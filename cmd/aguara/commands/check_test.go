package commands

import (
	"bytes"
	"context"
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
	// PR #5: the unsupported-ecosystem error now uses the
	// SupportedEcosystemsHint() format ("Maven (java)",
	// "NuGet (dotnet, csharp)"). Aliases stay lowercase but
	// canonical IDs are capitalised, so assert on a mix of
	// canonical-case canonical IDs and lowercase aliases.
	for _, eco := range []string{"npm", "PyPI", "Go", "crates.io", "Packagist", "RubyGems", "Maven", "NuGet"} {
		require.Contains(t, err.Error(), eco, "error must list %s", eco)
	}
	for _, alias := range []string{"python", "golang", "cargo", "rust", "php", "composer", "ruby", "java", "dotnet"} {
		require.Contains(t, err.Error(), alias, "error must list alias %s", alias)
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

// TestCheckEcosystemsJSONShape locks the raw JSON contract for the
// ecosystems[] field across the three CheckResult paths.
//
// The original purpose of this test was to prevent
// `"ecosystems": null` regressions: nil slices marshal as `null`,
// breaking pipelines that iterate the array unconditionally. That
// contract still holds for every path.
//
// What changed in #109: npm and PyPI incident paths now always
// append exactly one ecosystems[] entry per call (even when
// PackagesRead == 0), so JSON consumers see consistent coverage
// data. The go-on-empty-dir case still emits the empty array because
// the packagecheck path discovers zero lockfiles and dispatches
// nothing.
func TestCheckEcosystemsJSONShape(t *testing.T) {
	t.Run("ecosystem go on dir without go.sum still emits empty array", func(t *testing.T) {
		tmp := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(tmp, "README.md"), []byte("# nothing\n"), 0o644))
		raw := checkToFileRaw(t, "--ecosystem", "go", "--path", tmp)
		require.Contains(t, string(raw), `"ecosystems": []`)
		require.NotContains(t, string(raw), `"ecosystems": null`)
	})
	t.Run("ecosystem npm with empty node_modules appends an entry per #109", func(t *testing.T) {
		nm := filepath.Join(t.TempDir(), "node_modules")
		require.NoError(t, os.MkdirAll(nm, 0o755))
		raw := checkToFileRaw(t, "--ecosystem", "npm", "--path", nm)
		// The npm incident path runs unconditionally on the supplied
		// node_modules directory, so a per-call entry is appended
		// with PackagesRead=0 and FindingsCount=0. Important:
		// "ecosystems": null must NOT reappear (the v0.17.0
		// regression we're locking against).
		require.NotContains(t, string(raw), `"ecosystems": null`)
		require.NotContains(t, string(raw), `"ecosystems": []`,
			"empty array on empty node_modules contradicts #109: the npm path consumed the directory and must surface the entry")
		require.Contains(t, string(raw), `"ecosystem": "npm"`,
			"expected the npm entry to be present even with zero packages read")
		require.Contains(t, string(raw), `"source": "node_modules"`)
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

// --- PR #5: multi-ecosystem autodetect + explicit multi --ecosystem ---

func TestCheckMultiEcosystemAutodetectFindsAllEcosystemsInFixture(t *testing.T) {
	// The multi-all fixture has one lockfile per packagecheck
	// ecosystem (Go, Cargo, Composer, RubyGems, Maven, NuGet)
	// nested under separate service directories, plus a top-level
	// node_modules/ that triggers the npm incident path. Default
	// `aguara check --path <root>` must discover every one without
	// --ecosystem. npm and PyPI now emit ecosystems[] entries on the
	// incident path (issue #109), so the count is 7: 6 packagecheck
	// targets + 1 npm. The fixture has no Python site-packages
	// shape, so PyPI does not autodetect from this root and is not
	// in the expected set.
	result := checkToFile(t, "--path", "../../../internal/packagecheck/testdata/multi-all")

	require.Len(t, result.Ecosystems, 7, "expected 6 packagecheck targets + 1 npm autodetect, got %+v", result.Ecosystems)
	seen := map[string]bool{}
	for _, e := range result.Ecosystems {
		seen[e.Ecosystem] = true
	}
	for _, eco := range []string{"Go", "crates.io", "Packagist", "RubyGems", "Maven", "NuGet", "npm"} {
		require.True(t, seen[eco], "missing ecosystem %s in autodetect output (got %+v)", eco, seen)
	}
}

// --- Issue #111: aguara check [path] accepts an optional positional ---

func TestCheck_PositionalPath_Dot(t *testing.T) {
	// `aguara check .` must walk the current working directory.
	// The fixture lives at a known path; the test cd's into the
	// fixture root and calls `check .` so the positional `.`
	// resolves to that root.
	project := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(project, "node_modules"), 0o755))
	writeFakeNPMPackage(t, filepath.Join(project, "node_modules"), "lodash", "4.17.21")

	wd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(project))
	t.Cleanup(func() { _ = os.Chdir(wd) })

	result := checkToFile(t, ".")

	require.NotEmpty(t, result.Ecosystems, "positional '.' must resolve to the cwd and trigger the npm pipeline")
	require.Equal(t, "npm", result.Ecosystems[0].Ecosystem)
}

func TestCheck_PositionalPath_RelativeWithEcosystemFlag(t *testing.T) {
	// `aguara check ./fixtures --ecosystem npm` -- positional + flag
	// on a different axis must coexist. The positional supplies the
	// path; --ecosystem narrows the dispatch.
	project := t.TempDir()
	nm := filepath.Join(project, "node_modules")
	require.NoError(t, os.MkdirAll(nm, 0o755))
	writeFakeNPMPackage(t, nm, "lodash", "4.17.21")

	result := checkToFile(t, project, "--ecosystem", "npm")

	require.Len(t, result.Ecosystems, 1, "explicit --ecosystem npm with positional path must produce exactly one npm entry")
	require.Equal(t, "npm", result.Ecosystems[0].Ecosystem)
	require.Equal(t, 1, result.Ecosystems[0].PackagesRead)
}

func TestCheck_PositionalPath_PlusPathFlagIsAmbiguity(t *testing.T) {
	// Both forms together must fail with a clear ambiguity error.
	// The alternative ("flag wins silently") would surprise users
	// whose two paths point at different directories.
	a := t.TempDir()
	b := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(b, "node_modules"), 0o755))

	resetFlags()
	rootCmd.SetArgs([]string{"check", a, "--path", b, "--no-update-check"})
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		resetFlags()
	})

	err := rootCmd.Execute()
	require.Error(t, err, "passing both positional and --path must error, not silently pick one")
	require.Contains(t, err.Error(), "ambiguous path",
		"error message must name the ambiguity so the operator can drop one")
}

func TestCheck_PositionalPath_TwoArgsRejected(t *testing.T) {
	// `aguara check a b` must error via cobra.MaximumNArgs(1)
	// rather than silently using the first arg and dropping the
	// rest.
	resetFlags()
	rootCmd.SetArgs([]string{"check", "a", "b", "--no-update-check"})
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		resetFlags()
	})

	err := rootCmd.Execute()
	require.Error(t, err, "two positional args must error")
	require.Contains(t, err.Error(), "accepts at most 1 arg",
		"cobra's MaximumNArgs(1) error wording is the stable signal we lock against")
}

func TestCheck_ResolveCheckPathArg_TableSemantics(t *testing.T) {
	// Unit-level coverage of the precedence table for resolveCheckPathArg.
	// The CLI-level tests above exercise the full Cobra round-trip;
	// this one pins the contract at the helper boundary so the table
	// is reviewable in one place.
	cases := []struct {
		name      string
		args      []string
		flagPath  string
		want      string
		wantError bool
	}{
		{name: "empty/empty -> empty (legacy default)", args: nil, flagPath: "", want: ""},
		{name: "empty/flag -> flag", args: nil, flagPath: "/x", want: "/x"},
		{name: "positional/empty -> positional", args: []string{"/y"}, flagPath: "", want: "/y"},
		{name: "positional/flag -> error", args: []string{"/y"}, flagPath: "/x", wantError: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveCheckPathArg(tc.args, tc.flagPath)
			if tc.wantError {
				require.Error(t, err)
				require.Contains(t, err.Error(), "ambiguous path")
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// --- pnpm-lock.yaml coverage: npm ecosystem, packagecheck path ---

func TestCheckPlan_PnpmOnlyMapsToNPMToken(t *testing.T) {
	// pnpm-only autodetect plan (no node_modules, no other lockfiles)
	// has a single packagecheckTarget with Ecosystem=npm. The reverse
	// map osvIDToEcoToken does not include npm because npm normally
	// flows through the incident path, so singleEcoToken needs the
	// explicit npm short-circuit to return ecoNPM. Without it the
	// terminal formatter falls through to a wrong / generic label.
	plan, err := buildCheckPlan(nil, "../../../internal/packagecheck/testdata/pnpm-compromised")
	require.NoError(t, err)
	require.False(t, plan.runNPM, "fixture has no node_modules; incident.CheckNPM must not be triggered")
	require.Len(t, plan.packagecheckTargets, 1, "fixture has exactly one pnpm-lock.yaml target")
	require.Equal(t, "npm", plan.packagecheckTargets[0].Ecosystem)
	require.Equal(t, ecoNPM, plan.singleEcoToken(),
		"pnpm-only plan must report ecoNPM so the terminal label matches the pipeline that actually ran")
}

func TestCheck_PnpmLockCompromisedFixtureFiresFinding(t *testing.T) {
	// `aguara check <pnpm-repo>` on a fresh clone (no node_modules)
	// must detect node-ipc 9.2.3 in pnpm-lock.yaml. End-to-end
	// coverage of: discovery picks pnpm-lock.yaml as npm ecosystem,
	// ParsePNPMLock extracts the ref, matcher hits the embedded
	// node-ipc 9.2.3 record, finding is CRITICAL, ecosystems[]
	// entry reports source=pnpm-lock.yaml.
	result := checkToFile(t, "../../../internal/packagecheck/testdata/pnpm-compromised")

	require.Len(t, result.Ecosystems, 1, "exactly one ecosystems[] entry expected for pnpm-only fixture (no node_modules)")
	got := result.Ecosystems[0]
	require.Equal(t, "npm", got.Ecosystem)
	require.Equal(t, "pnpm-lock.yaml", got.Source)
	require.Contains(t, got.Path, "pnpm-lock.yaml")
	require.GreaterOrEqual(t, got.PackagesRead, 1, "lockfile has at least one declared package")
	require.GreaterOrEqual(t, got.FindingsCount, 1, "node-ipc@9.2.3 in the embedded compromised list must produce at least one finding")

	// Find the node-ipc finding in the flat findings slice.
	var nodeIPCFinding *incident.Finding
	for i := range result.Findings {
		if strings.Contains(result.Findings[i].Title, "node-ipc") {
			nodeIPCFinding = &result.Findings[i]
			break
		}
	}
	require.NotNil(t, nodeIPCFinding, "node-ipc finding missing; got: %+v", result.Findings)
	require.Equal(t, incident.SevCritical, nodeIPCFinding.Severity, "node-ipc 9.2.3 must be CRITICAL")
}

func TestCheck_PnpmLockCleanFixtureProducesZeroFindings(t *testing.T) {
	// Clean pnpm fixture (lodash + @types/node, neither
	// compromised) must produce zero findings while still emitting
	// the ecosystems[] entry so consumers see "pipeline ran, scanned
	// N packages, zero findings" rather than silence.
	result := checkToFile(t, "../../../internal/packagecheck/testdata/pnpm-clean")

	require.Len(t, result.Ecosystems, 1, "exactly one ecosystems[] entry expected")
	require.Equal(t, "npm", result.Ecosystems[0].Ecosystem)
	require.Equal(t, "pnpm-lock.yaml", result.Ecosystems[0].Source)
	require.GreaterOrEqual(t, result.Ecosystems[0].PackagesRead, 1)
	require.Equal(t, 0, result.Ecosystems[0].FindingsCount, "clean fixture must have zero findings")
	require.Empty(t, result.Findings, "top-level findings must be empty on clean fixture")
}

func TestCheck_PnpmLockMiniShaiHuludAntvFiresFinding(t *testing.T) {
	// Mini Shai-Hulud / @antv wave: `aguara check <pnpm-repo>` on a
	// fresh clone must detect the compromised @antv/g2 5.6.8 and
	// echarts-for-react 3.2.7 entries via the pnpm-lock.yaml path
	// without needing pnpm install to have run. End-to-end coverage:
	// autodetect picks pnpm-lock.yaml as npm ecosystem; parser
	// extracts both refs; matcher hits the manual incident entries
	// (these versions are NOT in the embedded OSV snapshot today,
	// which is why the manual intel exists).
	result := checkToFile(t, "../../../internal/packagecheck/testdata/pnpm-mini-shai-hulud-antv")

	require.Len(t, result.Ecosystems, 1)
	require.Equal(t, "npm", result.Ecosystems[0].Ecosystem)
	require.Equal(t, "pnpm-lock.yaml", result.Ecosystems[0].Source)
	require.GreaterOrEqual(t, result.Ecosystems[0].FindingsCount, 2,
		"@antv/g2 5.6.8 and echarts-for-react 3.2.7 must both fire")

	titles := make([]string, 0, len(result.Findings))
	for _, f := range result.Findings {
		require.Equal(t, incident.SevCritical, f.Severity,
			"all Mini Shai-Hulud findings must be CRITICAL, got %q on %q", f.Severity, f.Title)
		titles = append(titles, f.Title)
	}
	joined := strings.Join(titles, " | ")
	require.Contains(t, joined, "@antv/g2 5.6.8")
	require.Contains(t, joined, "echarts-for-react 3.2.7")
	require.Contains(t, joined, "SOCKET-2026-05-19-mini-shai-hulud-antv",
		"finding title must carry the advisory ID so dashboards can correlate")
}

func TestCheck_ExplicitNPMEcosystemOnPnpmRepoFires(t *testing.T) {
	// `aguara check --ecosystem npm --path <pnpm-only-repo>` must
	// scan pnpm-lock.yaml even though there's no node_modules. The
	// incident.CheckNPM pipeline is gated on node_modules existing;
	// the packagecheck pnpm discovery covers the pre-install case.
	result := checkToFile(t, "--ecosystem", "npm", "--path", "../../../internal/packagecheck/testdata/pnpm-compromised")

	require.Len(t, result.Ecosystems, 1, "pnpm-only repo with --ecosystem npm: exactly one ecosystems[] entry (pnpm-lock.yaml; incident.CheckNPM correctly skipped because node_modules absent)")
	require.Equal(t, "npm", result.Ecosystems[0].Ecosystem)
	require.Equal(t, "pnpm-lock.yaml", result.Ecosystems[0].Source)
	require.GreaterOrEqual(t, result.Ecosystems[0].FindingsCount, 1, "node-ipc 9.2.3 should fire")
}

func TestCheck_ExplicitNPMSoleEcosystemMissingSurfaceErrors(t *testing.T) {
	// `aguara check --ecosystem npm --path <empty-dir>` must keep
	// the legacy error contract (smoke-tested in
	// benchmarks/smoke-npm-incident.sh case 4): explicit npm with no
	// node_modules and no pnpm-lock.yaml is a user mistake, not a
	// clean result.
	empty := t.TempDir()

	resetFlags()
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{
		"check",
		"--ecosystem", "npm",
		"--path", empty,
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
	require.Error(t, err, "explicit --ecosystem npm with no npm surface must error")
	require.Contains(t, err.Error(), "npm check")
	require.Contains(t, err.Error(), "no node_modules tree")
}

func TestCheck_ExplicitNPMWithOtherEcosystemSkipsLegacyError(t *testing.T) {
	// `aguara check --ecosystem npm --ecosystem go --path <go-only>`
	// must NOT abort on the missing npm surface. The user is asking
	// for a multi-ecosystem audit; the discovered Go target should
	// still run. Regression guard against the v0.18.0 release-prep
	// commit where the explicit-npm error fired even when paired
	// with another ecosystem (codex P2).
	result := checkToFile(t,
		"--ecosystem", "npm",
		"--ecosystem", "go",
		"--path", "../../../internal/packagecheck/testdata/go-clean",
	)

	require.NotNil(t, result, "multi-ecosystem check must return a result, not error out")
	require.Len(t, result.Ecosystems, 1, "exactly one ecosystems[] entry expected (Go); npm has no surface here")
	require.Equal(t, "Go", result.Ecosystems[0].Ecosystem)
}

// --- package-lock.json coverage: npm ecosystem, packagecheck path ---

func TestCheckPlan_PackageLockOnlyMapsToNPMToken(t *testing.T) {
	// A package-lock.json-only repo (no node_modules, no other
	// lockfiles) autodetects to a single npm packagecheck target and
	// must report ecoNPM from singleEcoToken, same as the pnpm path.
	plan, err := buildCheckPlan(nil, "../../../internal/packagecheck/testdata/package-lock-compromised")
	require.NoError(t, err)
	require.False(t, plan.runNPM, "fixture has no node_modules; incident.CheckNPM must not be triggered")
	require.Len(t, plan.packagecheckTargets, 1, "fixture has exactly one package-lock.json target")
	require.Equal(t, "npm", plan.packagecheckTargets[0].Ecosystem)
	require.Equal(t, "package-lock.json", plan.packagecheckTargets[0].Source)
	require.Equal(t, ecoNPM, plan.singleEcoToken())
}

func TestCheck_PackageLockCompromisedFixtureFiresFinding(t *testing.T) {
	// `aguara check <npm-repo>` on a fresh clone (package-lock.json,
	// no node_modules) must detect node-ipc 9.2.3. End-to-end: autodetect
	// picks package-lock.json as npm ecosystem, ParsePackageLock extracts
	// the ref, matcher hits the embedded node-ipc record, ecosystems[]
	// entry reports source=package-lock.json.
	result := checkToFile(t, "../../../internal/packagecheck/testdata/package-lock-compromised")

	require.Len(t, result.Ecosystems, 1, "exactly one ecosystems[] entry expected (package-lock.json; no node_modules)")
	got := result.Ecosystems[0]
	require.Equal(t, "npm", got.Ecosystem)
	require.Equal(t, "package-lock.json", got.Source)
	require.Contains(t, got.Path, "package-lock.json")
	require.Equal(t, 2, got.PackagesRead, "node-ipc + lodash declared in the lockfile")
	require.GreaterOrEqual(t, got.FindingsCount, 1, "node-ipc@9.2.3 must produce at least one finding")

	var nodeIPCFinding *incident.Finding
	for i := range result.Findings {
		if strings.Contains(result.Findings[i].Title, "node-ipc") {
			nodeIPCFinding = &result.Findings[i]
			break
		}
	}
	require.NotNil(t, nodeIPCFinding, "node-ipc finding missing; got: %+v", result.Findings)
	require.Equal(t, incident.SevCritical, nodeIPCFinding.Severity, "node-ipc 9.2.3 must be CRITICAL")
}

func TestCheck_PackageLockCleanFixtureProducesZeroFindings(t *testing.T) {
	result := checkToFile(t, "../../../internal/packagecheck/testdata/package-lock-clean")

	require.Len(t, result.Ecosystems, 1)
	require.Equal(t, "npm", result.Ecosystems[0].Ecosystem)
	require.Equal(t, "package-lock.json", result.Ecosystems[0].Source)
	require.Equal(t, 2, result.Ecosystems[0].PackagesRead, "lodash + @types/node")
	require.Equal(t, 0, result.Ecosystems[0].FindingsCount, "clean fixture must have zero findings")
	require.Empty(t, result.Findings)
}

func TestCheck_ExplicitNPMOnPackageLockOnlyRepoFires(t *testing.T) {
	// Product check from the P3 spec: `aguara check --ecosystem npm
	// --path <fresh clone with only package-lock.json>` must scan the
	// lockfile (no node_modules required) and report source=package-lock.json.
	result := checkToFile(t, "--ecosystem", "npm", "--path", "../../../internal/packagecheck/testdata/package-lock-compromised")

	require.Len(t, result.Ecosystems, 1, "package-lock-only repo with --ecosystem npm: one ecosystems[] entry")
	require.Equal(t, "npm", result.Ecosystems[0].Ecosystem)
	require.Equal(t, "package-lock.json", result.Ecosystems[0].Source)
	require.GreaterOrEqual(t, result.Ecosystems[0].FindingsCount, 1, "node-ipc 9.2.3 should fire")
}

func TestCheck_PackageLockAliasCatchesRealPackage(t *testing.T) {
	// A dependency aliased as `"safe-ipc": "npm:node-ipc@9.2.3"` must
	// be caught as the real node-ipc 9.2.3, not slip through under the
	// innocuous alias directory name. End-to-end through the matcher.
	result := checkToFile(t, "../../../internal/packagecheck/testdata/package-lock-alias")

	require.Len(t, result.Ecosystems, 1)
	require.Equal(t, "package-lock.json", result.Ecosystems[0].Source)
	require.Equal(t, 1, result.Ecosystems[0].PackagesRead, "one alias entry resolves to one real package")
	require.GreaterOrEqual(t, result.Ecosystems[0].FindingsCount, 1, "aliased node-ipc 9.2.3 must still fire")

	var nodeIPCFinding *incident.Finding
	for i := range result.Findings {
		if strings.Contains(result.Findings[i].Title, "node-ipc") {
			nodeIPCFinding = &result.Findings[i]
			break
		}
	}
	require.NotNil(t, nodeIPCFinding, "aliased dependency must be reported as node-ipc; got: %+v", result.Findings)
	for _, f := range result.Findings {
		require.NotContains(t, f.Title, "safe-ipc", "the alias name must never appear as a package")
	}
}

// --- yarn.lock (classic v1) coverage: npm ecosystem, packagecheck path ---

func TestCheckPlan_YarnLockOnlyMapsToNPMToken(t *testing.T) {
	plan, err := buildCheckPlan(nil, "../../../internal/packagecheck/testdata/yarn-lock-compromised")
	require.NoError(t, err)
	require.False(t, plan.runNPM, "fixture has no node_modules; incident.CheckNPM must not be triggered")
	require.Len(t, plan.packagecheckTargets, 1, "fixture has exactly one yarn.lock target")
	require.Equal(t, "npm", plan.packagecheckTargets[0].Ecosystem)
	require.Equal(t, "yarn.lock", plan.packagecheckTargets[0].Source)
	require.Equal(t, ecoNPM, plan.singleEcoToken())
}

func TestCheck_YarnLockCompromisedFixtureFiresFinding(t *testing.T) {
	// `aguara check <yarn-repo>` on a fresh clone (yarn.lock, no
	// node_modules) must detect node-ipc 9.2.3. End-to-end: autodetect
	// picks yarn.lock as npm ecosystem, ParseYarnLock extracts the
	// ref, matcher hits the embedded node-ipc record.
	result := checkToFile(t, "../../../internal/packagecheck/testdata/yarn-lock-compromised")

	require.Len(t, result.Ecosystems, 1)
	got := result.Ecosystems[0]
	require.Equal(t, "npm", got.Ecosystem)
	require.Equal(t, "yarn.lock", got.Source)
	require.Contains(t, got.Path, "yarn.lock")
	require.Equal(t, 2, got.PackagesRead, "node-ipc + lodash declared in the lockfile")
	require.GreaterOrEqual(t, got.FindingsCount, 1, "node-ipc@9.2.3 must produce at least one finding")

	var nodeIPCFinding *incident.Finding
	for i := range result.Findings {
		if strings.Contains(result.Findings[i].Title, "node-ipc") {
			nodeIPCFinding = &result.Findings[i]
			break
		}
	}
	require.NotNil(t, nodeIPCFinding, "node-ipc finding missing; got: %+v", result.Findings)
	require.Equal(t, incident.SevCritical, nodeIPCFinding.Severity, "node-ipc 9.2.3 must be CRITICAL")
}

func TestCheck_YarnLockCleanFixtureProducesZeroFindings(t *testing.T) {
	result := checkToFile(t, "../../../internal/packagecheck/testdata/yarn-lock-clean")

	require.Len(t, result.Ecosystems, 1)
	require.Equal(t, "npm", result.Ecosystems[0].Ecosystem)
	require.Equal(t, "yarn.lock", result.Ecosystems[0].Source)
	require.Equal(t, 2, result.Ecosystems[0].PackagesRead, "lodash + @types/node")
	require.Equal(t, 0, result.Ecosystems[0].FindingsCount, "clean fixture must have zero findings")
	require.Empty(t, result.Findings)
}

func TestCheck_ExplicitNPMOnYarnLockOnlyRepoFires(t *testing.T) {
	// `aguara check --ecosystem npm --path <yarn.lock-only repo>` must
	// scan the lockfile (no node_modules required).
	result := checkToFile(t, "--ecosystem", "npm", "--path", "../../../internal/packagecheck/testdata/yarn-lock-compromised")

	require.Len(t, result.Ecosystems, 1)
	require.Equal(t, "npm", result.Ecosystems[0].Ecosystem)
	require.Equal(t, "yarn.lock", result.Ecosystems[0].Source)
	require.GreaterOrEqual(t, result.Ecosystems[0].FindingsCount, 1, "node-ipc 9.2.3 should fire")
}

func TestCheck_YarnBerryLockfileFailsLoudly(t *testing.T) {
	// A yarn Berry (v2+) lockfile is not parsed yet. Rather than pass
	// silently with zero packages read (which could slip through
	// --ci), `aguara check` must fail with a clear error so the user
	// knows the lockfile went unaudited.
	dir := t.TempDir()
	berry := "# This file is generated by running \"yarn install\"\n__metadata:\n  version: 6\n\n\"lodash@npm:^4.17.21\":\n  version: 4.17.21\n  resolution: \"lodash@npm:4.17.21\"\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "yarn.lock"), []byte(berry), 0o600))

	resetFlags()
	rootCmd.SetOut(new(bytes.Buffer))
	rootCmd.SetErr(new(bytes.Buffer))
	rootCmd.SetArgs([]string{"check", "--ecosystem", "npm", "--path", dir, "--format", "json", "--no-update-check"})
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		resetFlags()
	})

	err := rootCmd.Execute()
	require.Error(t, err, "Berry lockfile must make aguara check fail loudly")
	require.Contains(t, err.Error(), "Berry")
}

// --- Issue #109: npm and PyPI emit ecosystems[] entries on the incident path ---

func TestCheckExplicitNPM_AppendsEcosystemsEntry(t *testing.T) {
	// `aguara check --ecosystem npm --path <node_modules>` must
	// surface an ecosystems[] entry alongside any findings so JSON
	// consumers reading the array see consistent multi-ecosystem
	// coverage data. Before #109 fix, ecosystems[] was always [] for
	// the npm path, contradicting the "npm scanned" reality.
	nm := filepath.Join(t.TempDir(), "node_modules")
	require.NoError(t, os.MkdirAll(nm, 0o755))
	writeFakeNPMPackage(t, nm, "express", "4.18.2")
	writeFakeNPMPackage(t, nm, "lodash", "4.17.21")

	result := checkToFile(t, "--ecosystem", "npm", "--path", nm)

	require.Len(t, result.Ecosystems, 1, "expected exactly one ecosystems[] entry for explicit npm path")
	got := result.Ecosystems[0]
	require.Equal(t, "npm", got.Ecosystem)
	require.Equal(t, "node_modules", got.Source)
	require.Equal(t, nm, got.Path)
	require.Equal(t, 2, got.PackagesRead, "fixture has express + lodash")
	require.Equal(t, 0, got.FindingsCount, "neither package is compromised; findings_count should be 0")
}

func TestCheckExplicitPython_AppendsEcosystemsEntry(t *testing.T) {
	// `aguara check --ecosystem python --path <site-packages>` must
	// surface an ecosystems[] entry. Builds a minimal site-packages
	// shape (one dist-info) so the PyPI path runs and counts the
	// package without producing findings.
	siteDir := t.TempDir()
	distInfo := filepath.Join(siteDir, "requests-2.31.0.dist-info")
	require.NoError(t, os.Mkdir(distInfo, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(distInfo, "METADATA"), []byte(
		"Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\n",
	), 0o644))

	result := checkToFile(t, "--ecosystem", "python", "--path", siteDir)

	require.Len(t, result.Ecosystems, 1, "expected exactly one ecosystems[] entry for explicit python path")
	got := result.Ecosystems[0]
	require.Equal(t, "PyPI", got.Ecosystem)
	require.Equal(t, "site-packages", got.Source)
	require.Equal(t, siteDir, got.Path)
	require.Equal(t, 1, got.PackagesRead, "fixture has one dist-info package")
	require.Equal(t, 0, got.FindingsCount, "requests 2.31.0 is not in the compromised list")
}

func TestCheckExplicitMultiEcosystemFlag(t *testing.T) {
	// `--ecosystem go,ruby` constrains the scan to two pipelines
	// even though the fixture has six lockfiles.
	result := checkToFile(t, "--ecosystem", "go,ruby", "--path", "../../../internal/packagecheck/testdata/multi-all")

	require.Len(t, result.Ecosystems, 2, "expected exactly Go + RubyGems, got %+v", result.Ecosystems)
	seen := map[string]bool{}
	for _, e := range result.Ecosystems {
		seen[e.Ecosystem] = true
	}
	require.True(t, seen["Go"], "expected Go in ecosystems")
	require.True(t, seen["RubyGems"], "expected RubyGems in ecosystems")
}

func TestCheckRepeatedEcosystemFlagAggregates(t *testing.T) {
	// `--ecosystem go --ecosystem ruby` must produce the same
	// plan as the comma-separated form.
	result := checkToFile(t, "--ecosystem", "go", "--ecosystem", "ruby", "--path", "../../../internal/packagecheck/testdata/multi-all")

	require.Len(t, result.Ecosystems, 2)
	seen := map[string]bool{}
	for _, e := range result.Ecosystems {
		seen[e.Ecosystem] = true
	}
	require.True(t, seen["Go"] && seen["RubyGems"])
}

func TestCheckExplicitPathEmptyDirReturnsCleanResult(t *testing.T) {
	// Spec contract: an explicit --path with no signals must
	// return a clean result, NOT fall through to Python's global
	// site-packages autodiscovery. The JSON shape stays
	// `"ecosystems": []` so consumers iterating the slice never
	// see surprise Python findings from /usr/lib/python*.
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "README.md"), []byte("# nothing\n"), 0o644))

	raw := checkToFileRaw(t, "--path", tmp)
	require.Contains(t, string(raw), `"ecosystems": []`)
	require.NotContains(t, string(raw), `"ecosystems": null`)
	require.NotContains(t, string(raw), `site-packages`, "explicit --path with no signals must NOT trigger Python global discovery")
}

func TestCheckPlanIntelEcosystemsScopesFreshRefresh(t *testing.T) {
	// --fresh + --ecosystem maven must refresh ONLY Maven, not
	// the legacy default of [npm, PyPI]. We assert at the
	// checkPlan level (the same struct resolveCheckIntel
	// consumes) so the test does not require a live network.
	tmp := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmp, "svc-maven"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "svc-maven", "pom.xml"), []byte(`<?xml version="1.0"?><project><modelVersion>4.0.0</modelVersion><groupId>g</groupId><artifactId>a</artifactId><version>1</version><dependencies><dependency><groupId>org.example</groupId><artifactId>lib</artifactId><version>1.0.0</version></dependency></dependencies></project>`), 0o644))

	plan, err := buildCheckPlan([]string{"maven"}, tmp)
	require.NoError(t, err)
	require.Equal(t, []string{"Maven"}, plan.intelEcosystems(), "--ecosystem maven must scope intel refresh to Maven only")
}

func TestCheckPlanIntelEcosystemsForAutodetect(t *testing.T) {
	// Autodetect plan's intelEcosystems must list every OSV
	// bucket the plan touches so --fresh refreshes the right
	// set.
	plan, err := buildCheckPlan(nil, "../../../internal/packagecheck/testdata/multi-all")
	require.NoError(t, err)
	got := plan.intelEcosystems()
	for _, want := range []string{"Go", "crates.io", "Packagist", "RubyGems", "Maven", "NuGet"} {
		require.Contains(t, got, want, "autodetect plan must include %s in intel refresh set", want)
	}
}

// --- PR #5 blocker 1: --fresh must scope to requested ecosystems even when discovery is empty ---

func TestCheckPlanIntelEcosystemsExplicitNoTargets(t *testing.T) {
	// --ecosystem maven --path <empty-dir> must keep "Maven"
	// in intelEcosystems() so a follow-up --fresh refreshes
	// Maven specifically, not the legacy default-all.
	tmp := t.TempDir()
	plan, err := buildCheckPlan([]string{"maven"}, tmp)
	require.NoError(t, err)
	require.Equal(t, []string{"Maven"}, plan.intelEcosystems(), "explicit --ecosystem must survive empty discovery so --fresh stays scoped")
	require.True(t, plan.explicitEcosystem)
	require.Empty(t, plan.packagecheckTargets, "discovery walked an empty dir; no targets expected")
}

func TestCheckPlanIntelEcosystemsExplicitMultipleNoTargets(t *testing.T) {
	tmp := t.TempDir()
	plan, err := buildCheckPlan([]string{"maven", "ruby"}, tmp)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"Maven", "RubyGems"}, plan.intelEcosystems())
}

func TestCheckPlanIntelEcosystemsAutodetectEmptyExplicitPath(t *testing.T) {
	// Autodetect on an explicit empty path produces an empty
	// plan (no Python fallback, per the spec contract). The
	// empty intelEcosystems() is what resolveCheckIntel uses
	// to skip the --fresh network call entirely.
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "README.md"), []byte("# nothing\n"), 0o644))
	plan, err := buildCheckPlan(nil, tmp)
	require.NoError(t, err)
	require.Empty(t, plan.intelEcosystems(), "autodetect with no signals must leave intelEcosystems empty so --fresh does not fall through to default-all")
	require.False(t, plan.explicitEcosystem)
}

func TestResolveCheckIntelSkipsFreshWhenPlanIsEmpty(t *testing.T) {
	// Spec: --fresh on an empty plan must NOT trigger
	// intel.Update's empty-default refresh-all-ecosystems path.
	// resolveCheckIntel takes the safe answer (local /
	// embedded) and does no network I/O. We assert by enabling
	// --fresh + an empty ecosystems list and a context that
	// would cancel any real HTTP attempt before it could finish;
	// the call must succeed without ever hitting the network.
	resetFlags()
	t.Cleanup(resetFlags)
	flagCheckFresh = true
	flagCheckAllowStale = false

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // ensure any actual HTTP attempt would fail fast.

	override, err := resolveCheckIntel(ctx, nil)
	require.NoError(t, err, "--fresh with empty ecosystem list must succeed without making a network call")
	// override may be nil (no local snapshot) or non-nil
	// (local snapshot exists); both are valid "no fresh refresh"
	// outcomes. The contract is that we did not error and did
	// not declare an "online" / "remote-fresh" mode.
	if override != nil {
		require.NotEqual(t, "remote-fresh", override.SnapshotLabel, "empty plan must not declare a remote-fresh refresh")
	}
}

func TestCheckSingleEcoTokenHonoursExplicitEcosystemWithEmptyDiscovery(t *testing.T) {
	// `aguara check --ecosystem maven --path <empty-dir>` must
	// label the terminal output "Maven / Gradle dependencies"
	// instead of falling through to the Python default + the
	// ".pth files scanned" line.
	tmp := t.TempDir()
	plan, err := buildCheckPlan([]string{"maven"}, tmp)
	require.NoError(t, err)
	require.Equal(t, ecoMaven, plan.singleEcoToken(), "explicit Maven request with empty discovery must keep the Maven label")
}
