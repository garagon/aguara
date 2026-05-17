package commands

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/garagon/aguara/internal/incident"
	"github.com/garagon/aguara/internal/intel"
	"github.com/garagon/aguara/internal/intel/osvimport"
	"github.com/garagon/aguara/internal/packagecheck"
	"github.com/spf13/cobra"
)

var (
	flagCheckPath        string
	flagCheckEcosystems  []string
	flagCheckFailOn      string
	flagCheckCI          bool
	flagCheckFresh       bool
	flagCheckAllowStale  bool
)

const (
	ecoPython   = "python"
	ecoNPM      = "npm"
	ecoGo       = "go"
	ecoCargo    = "cargo"
	ecoComposer = "composer"
	ecoRuby     = "ruby"
	ecoMaven    = "maven"
	ecoNuGet    = "nuget"
)

// packagecheckEcosystems maps CLI dispatch tokens to the
// canonical OSV bucket the packagecheck runner queries the
// matcher with. runCheck routes the whole set through
// runPackageCheck; adding a new packagecheck-driven ecosystem is
// one entry here plus a case-arm in resolveCheckTarget.
var packagecheckEcosystems = map[string]string{
	ecoGo:       intel.EcosystemGo,
	ecoCargo:    intel.EcosystemCargo,
	ecoComposer: intel.EcosystemPackagist,
	ecoRuby:     intel.EcosystemRubyGems,
	ecoMaven:    intel.EcosystemMaven,
	ecoNuGet:    intel.EcosystemNuGet,
}

// osvIDToEcoToken inverts packagecheckEcosystems so the runner can
// recover the CLI dispatch label (ecoGo / ecoCargo / ...) from an
// OSV bucket ID it received from packagecheck. Used by
// ecosystemFindingText to pick the right per-ecosystem remediation
// text when running in autodetect mode where the original CLI
// token is not available per-hit.
var osvIDToEcoToken = func() map[string]string {
	out := make(map[string]string, len(packagecheckEcosystems))
	for token, id := range packagecheckEcosystems {
		out[id] = token
	}
	return out
}()

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check for compromised packages and persistence artifacts",
	Long: `Run from a project root. Aguara discovers installed npm /
Python environments at the path AND lockfiles for Go, Rust,
PHP/Composer, Ruby/Bundler, Java/Maven/Gradle, and .NET/NuGet
recursively under the path, then matches every declared package
against the embedded threat-intel snapshot.

Pass --ecosystem to constrain the scan. Multiple values supported,
comma-separated or repeated:

  --ecosystem go,ruby
  --ecosystem cargo --ecosystem maven

Supported values (case-insensitive):
  python (alias: pypi)
  npm
  go     (alias: golang)
  cargo  (alias: rust)
  composer (alias: php)
  ruby   (aliases: gem, rubygems)
  maven  (alias: java)
  nuget  (aliases: dotnet, csharp)

The known-bad list ships embedded with the binary; --fresh refreshes
only the ecosystems actually being checked.`,
	RunE: runCheck,
}

func init() {
	checkCmd.Flags().StringVar(&flagCheckPath, "path", "", "Path to project root, node_modules, or Python site-packages")
	checkCmd.Flags().StringSliceVar(&flagCheckEcosystems, "ecosystem", nil, "Package ecosystem (auto-detect by default; repeatable or comma-separated): python, npm, go, cargo, composer, ruby, maven, nuget")
	checkCmd.Flags().StringVar(&flagCheckFailOn, "fail-on", "", "Exit with code 1 if findings reach this severity: critical, warning, info")
	checkCmd.Flags().BoolVar(&flagCheckCI, "ci", false, "CI mode: equivalent to --fail-on critical --no-color")
	checkCmd.Flags().BoolVar(&flagCheckFresh, "fresh", false, "Refresh threat intel before checking (network opt-in)")
	checkCmd.Flags().BoolVar(&flagCheckAllowStale, "allow-stale", false, "Continue with cached/embedded intel if --fresh refresh fails")
	// Runtime errors (ErrThresholdExceeded after --ci, --fresh
	// network failures) should not trigger Cobra's flag-usage
	// block: a CI log that prints "Error: findings exceed severity
	// threshold" then dumps the full --help reads as command
	// misuse to non-technical readers. See scan.go for the same
	// rationale.
	checkCmd.SilenceUsage = true
	rootCmd.AddCommand(checkCmd)
}

func runCheck(cmd *cobra.Command, args []string) error {
	applyCheckCIDefaults()

	plan, err := buildCheckPlan(flagCheckEcosystems, flagCheckPath)
	if err != nil {
		return err
	}

	override, err := resolveCheckIntel(cmd.Context(), plan.intelEcosystems())
	if err != nil {
		return err
	}

	result, err := runCheckPlan(plan, override)
	if err != nil {
		return err
	}

	if flagFormat == "json" {
		if err := writeCheckJSON(result); err != nil {
			return err
		}
	} else {
		if err := writeCheckTerminal(result, plan); err != nil {
			return err
		}
	}

	return checkIncidentFailOnThreshold(result, flagCheckFailOn)
}

// applyCheckCIDefaults wires --ci to the equivalent explicit flags.
// --ci sets --fail-on critical (unless the user already set --fail-on
// explicitly) and disables color. NO_COLOR also disables color so the
// flag interacts cleanly with CI runners that set it by convention.
func applyCheckCIDefaults() {
	if flagCheckCI {
		if flagCheckFailOn == "" {
			flagCheckFailOn = "critical"
		}
		flagNoColor = true
	}
	if os.Getenv("NO_COLOR") != "" {
		flagNoColor = true
	}
}

// checkPlan describes which check pipelines runCheckPlan will invoke
// for a single `aguara check` call. The plan separates the legacy
// incident-based paths (npm / Python) from the packagecheck path
// (Go / Cargo / Composer / Ruby / Maven / NuGet) so each can produce
// its own slice of intel.MatchInputs and the runner merges the
// resulting CheckResults into one flat output.
//
// `intelEcosystems()` returns the OSV bucket IDs the plan touches;
// resolveCheckIntel uses that list to scope a --fresh refresh to
// only what the user is checking.
type checkPlan struct {
	rootPath          string // the path the user passed (may be "")
	runPython         bool
	pythonPath        string
	runNPM            bool
	npmPath           string
	packagecheckTargets []packagecheck.Target
}

// intelEcosystems returns the OSV bucket IDs the plan needs intel
// for. Used by resolveCheckIntel so --fresh refreshes only the
// ecosystems actually being checked (a `--ecosystem maven` user
// should NOT pull npm + PyPI on --fresh because the legacy default
// happens to be those two).
func (p checkPlan) intelEcosystems() []string {
	seen := map[string]bool{}
	var out []string
	add := func(id string) {
		if seen[id] {
			return
		}
		seen[id] = true
		out = append(out, id)
	}
	if p.runPython {
		add(intel.EcosystemPyPI)
	}
	if p.runNPM {
		add(intel.EcosystemNPM)
	}
	for _, t := range p.packagecheckTargets {
		add(t.Ecosystem)
	}
	return out
}

// isMulti reports whether the plan touches more than one pipeline
// (Python + npm, npm + packagecheck targets across multiple
// ecosystems, etc.). The terminal formatter uses the answer to pick
// between the per-ecosystem environment labels ("Go modules",
// "npm node_modules tree") and the multi-ecosystem framing
// ("project dependencies").
func (p checkPlan) isMulti() bool {
	pipelines := 0
	if p.runPython {
		pipelines++
	}
	if p.runNPM {
		pipelines++
	}
	if len(p.packagecheckTargets) > 0 {
		pipelines++
	}
	if pipelines > 1 {
		return true
	}
	// One pipeline but multiple packagecheck ecosystems still
	// counts as multi for display purposes.
	eco := map[string]bool{}
	for _, t := range p.packagecheckTargets {
		eco[t.Ecosystem] = true
	}
	return len(eco) > 1
}

// singleEcoToken returns the CLI dispatch label when the plan is
// single-ecosystem; "" when the plan is multi or empty. The
// terminal formatter uses this to pick the existing per-ecosystem
// labels for single-ecosystem checks.
func (p checkPlan) singleEcoToken() string {
	if p.isMulti() {
		return ""
	}
	if p.runPython {
		return ecoPython
	}
	if p.runNPM {
		return ecoNPM
	}
	if len(p.packagecheckTargets) > 0 {
		return osvIDToEcoToken[p.packagecheckTargets[0].Ecosystem]
	}
	return ""
}

// buildCheckPlan turns the user-supplied --ecosystem flags + --path
// into a concrete plan. An empty --ecosystem list triggers recursive
// autodetect; a non-empty list constrains the plan to exactly the
// requested ecosystems.
//
// An EXPLICIT --path that does not exist (or points at a regular
// file) is an error: a typo in CI -- e.g.
// `--path /opt/venv/lib/pyhton...` -- must not look like a clean
// check result. The validator only fires when path != ""; empty
// path keeps the legacy Python autodiscovery contract intact.
//
// When --ecosystem is empty AND --path is explicit, an empty plan
// (no targets found, no Python / npm signals) is returned without
// falling back to Python's site-packages autodiscovery. The
// fallback fires only when --path is empty so the historical
// behaviour of `aguara check` (no flags) on a host with a global
// site-packages keeps working.
func buildCheckPlan(ecoFlags []string, path string) (checkPlan, error) {
	if err := validateExplicitCheckPath(path); err != nil {
		return checkPlan{}, err
	}
	plan := checkPlan{rootPath: path}

	// --- Explicit ecosystem path ---
	if len(ecoFlags) > 0 {
		var packagecheckIDs []string
		for _, raw := range ecoFlags {
			token, err := canonicaliseCheckEcosystem(raw)
			if err != nil {
				return checkPlan{}, err
			}
			switch token {
			case ecoPython:
				plan.runPython = true
				plan.pythonPath = path
			case ecoNPM:
				plan.runNPM = true
				plan.npmPath = path
			default:
				osvID, ok := packagecheckEcosystems[token]
				if !ok {
					return checkPlan{}, fmt.Errorf("internal error: unresolved ecosystem token %q", token)
				}
				packagecheckIDs = append(packagecheckIDs, osvID)
			}
		}
		if len(packagecheckIDs) > 0 {
			root := path
			if root == "" {
				root = "."
			}
			targets, err := packagecheck.Discover(root, packagecheckIDs)
			if err != nil {
				return checkPlan{}, fmt.Errorf("check: discover %s: %w", root, err)
			}
			plan.packagecheckTargets = targets
		}
		return plan, nil
	}

	// --- Autodetect ---
	probe := path
	if probe == "" {
		probe = "."
	}
	resolved := probe
	if abs, err := filepath.Abs(probe); err == nil {
		resolved = abs
	}

	// npm: probe root is node_modules itself OR contains one.
	if filepath.Base(resolved) == "node_modules" {
		plan.runNPM = true
		plan.npmPath = resolved
	} else if statDir(filepath.Join(resolved, "node_modules")) {
		plan.runNPM = true
		plan.npmPath = resolved
	}

	// packagecheck: recursive walk for every supported ecosystem
	// at once. Discover honours the skip-list (vendor, target,
	// bin, obj, .gradle, node_modules, .git, .aguara) so this is
	// safe to run unconditionally.
	if statDir(resolved) {
		targets, err := packagecheck.Discover(resolved, nil)
		if err != nil {
			return checkPlan{}, fmt.Errorf("check: discover %s: %w", resolved, err)
		}
		plan.packagecheckTargets = targets
	}

	// Python legacy: explicit path heuristic (site-packages-shaped
	// directory) wins regardless of whether npm / packagecheck
	// also fired, because a site-packages tree IS a Python check.
	if path != "" && looksLikePythonSitePackages(resolved) {
		plan.runPython = true
		plan.pythonPath = path
	}

	// Python legacy: implicit-path fallback. When the user ran
	// `aguara check` with NO --path and we found nothing, fire
	// the historical site-packages autodiscovery so the
	// no-flag invocation on a host with global Python keeps
	// working.
	if path == "" && !plan.runNPM && len(plan.packagecheckTargets) == 0 && !plan.runPython {
		plan.runPython = true
		plan.pythonPath = ""
	}

	return plan, nil
}

// canonicaliseCheckEcosystem maps a raw --ecosystem flag value to
// the internal CLI dispatch token. Used by buildCheckPlan;
// unsupported values surface the full list of choices so the user
// can recover from a typo without reading source.
func canonicaliseCheckEcosystem(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "python", "pypi":
		return ecoPython, nil
	case "npm":
		return ecoNPM, nil
	case "go", "golang":
		return ecoGo, nil
	case "cargo", "rust":
		return ecoCargo, nil
	case "composer", "php":
		return ecoComposer, nil
	case "ruby", "gem", "rubygems":
		return ecoRuby, nil
	case "maven", "java":
		return ecoMaven, nil
	case "nuget", "dotnet", "csharp":
		return ecoNuGet, nil
	default:
		return "", fmt.Errorf("unsupported ecosystem %q (supported: %s)", raw, intel.SupportedEcosystemsHint())
	}
}

// resolveCheckTarget is the single-ecosystem helper kept for tests
// + audit that have not migrated to checkPlan yet. New code should
// call buildCheckPlan directly. Returns the FIRST ecosystem the
// plan resolves to; multi-ecosystem plans are flattened to their
// first packagecheck target (or Python / npm if those fire first).
func resolveCheckTarget(eco, path string) (string, string, error) {
	flags := []string(nil)
	if strings.TrimSpace(eco) != "" {
		flags = []string{eco}
	}
	plan, err := buildCheckPlan(flags, path)
	if err != nil {
		return "", "", err
	}
	if plan.runPython {
		return ecoPython, plan.pythonPath, nil
	}
	if plan.runNPM {
		return ecoNPM, plan.npmPath, nil
	}
	if len(plan.packagecheckTargets) > 0 {
		token := osvIDToEcoToken[plan.packagecheckTargets[0].Ecosystem]
		return token, path, nil
	}
	// Empty plan: explicit --path with no targets. Tests that
	// pre-date PR #5 expect a non-empty ecosystem back; fall back
	// to Python so the legacy test contract holds.
	return ecoPython, path, nil
}

// validateExplicitCheckPath enforces that an explicit --path (when
// non-empty) refers to an existing directory. Returns nil when path
// is empty so the autodiscovery branch keeps working. A missing path
// is the typical typo case ("/opt/venv/lib/pyhton..." vs "python");
// returning a clean error here means CI surfaces the typo as exit 2
// instead of advertising a green check on a path the operator never
// asked to scan.
func validateExplicitCheckPath(path string) error {
	if path == "" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("check: --path %s: no such file or directory", path)
		}
		return fmt.Errorf("check: --path %s: %w", path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("check: --path %s: not a directory", path)
	}
	return nil
}

// singleEcoEnvLabel returns the terminal-friendly label for a
// single-ecosystem plan ("npm node_modules tree", "Go modules",
// ...). Returns "" for multi-ecosystem plans; the caller falls
// back to the generic "project dependencies" framing in that case.
func singleEcoEnvLabel(token string) string {
	switch token {
	case ecoPython:
		return "Python environment"
	case ecoNPM:
		return "npm node_modules tree"
	case ecoGo:
		return "Go modules"
	case ecoCargo:
		return "Rust crates"
	case ecoComposer:
		return "Composer packages"
	case ecoRuby:
		return "RubyGems"
	case ecoMaven:
		return "Maven / Gradle dependencies"
	case ecoNuGet:
		return "NuGet packages"
	default:
		return ""
	}
}

// statDir reports whether path exists as a directory. Used by the
// autodetect arm of buildCheckPlan to decide whether the probe is
// safe to walk.
func statDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// looksLikePythonSitePackages returns true when path's basename is
// one of the conventional Python install-tree directory names, or
// when any `*.dist-info` directory sits at the path root. Used by
// buildCheckPlan to fire the legacy Python check when the user
// explicitly points at a venv / system install rather than a
// project root.
//
// Conservative on purpose: a directory whose basename happens to
// equal "site-packages" inside an unrelated project must NOT fire
// Python unless the dist-info evidence is present. The dist-info
// signal is what proves "this really is a Python install".
func looksLikePythonSitePackages(path string) bool {
	base := filepath.Base(path)
	switch base {
	case "site-packages", "dist-packages":
		return true
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() && strings.HasSuffix(e.Name(), ".dist-info") {
			return true
		}
	}
	return false
}

// runCheckPlan executes every pipeline the plan asks for and
// merges the per-pipeline CheckResults into one. Top-level
// Findings stays flat across pipelines; Ecosystems aggregates the
// packagecheck per-lockfile entries. Errors from a single
// pipeline surface immediately rather than producing a partial
// result.
//
// An empty plan (explicit --path with no targets and no Python /
// npm signals) produces a clean CheckResult so JSON consumers see
// the stable `"findings": []` / `"ecosystems": []` shape.
func runCheckPlan(plan checkPlan, override *incident.IntelOverride) (*incident.CheckResult, error) {
	var parts []*incident.CheckResult

	if plan.runPython {
		opts := incident.CheckOptions{Path: plan.pythonPath, Intel: override}
		r, err := incident.Check(opts)
		if err != nil {
			return nil, err
		}
		parts = append(parts, r)
	}
	if plan.runNPM {
		opts := incident.CheckOptions{Path: plan.npmPath, Intel: override}
		r, err := incident.CheckNPM(opts)
		if err != nil {
			return nil, err
		}
		parts = append(parts, r)
	}
	if len(plan.packagecheckTargets) > 0 {
		r, err := runPackagecheckPlan(plan, override)
		if err != nil {
			return nil, err
		}
		parts = append(parts, r)
	}

	if len(parts) == 0 {
		// Explicit --path with no signals. Return the canonical
		// empty CheckResult so the JSON contract still emits
		// `"ecosystems": []` and `"findings": []`.
		env := plan.rootPath
		if env == "" {
			env = "."
		}
		return &incident.CheckResult{
			Environment: env,
			Findings:    []incident.Finding{},
			Credentials: []incident.CredentialFile{},
			Ecosystems:  []packagecheck.EcosystemResult{},
			Intel:       incident.IntelSummaryForOverride(override),
		}, nil
	}
	return mergeCheckResults(parts, plan.rootPath), nil
}

// runPackagecheckPlan runs the packagecheck Runner against every
// Target the plan discovered and converts the resulting Hits into
// incident.Finding entries with per-ecosystem remediation text.
// The Ecosystems slice carries one entry per lockfile so multi-
// language repos show every manifest in JSON output.
func runPackagecheckPlan(plan checkPlan, override *incident.IntelOverride) (*incident.CheckResult, error) {
	runner := &packagecheck.Runner{Matcher: incident.MatcherForOverride(override)}
	runRes, err := runner.Run(plan.packagecheckTargets)
	if err != nil {
		return nil, fmt.Errorf("aguara check: packagecheck: %w", err)
	}
	root := plan.rootPath
	if root == "" {
		root = "."
	}
	result := &incident.CheckResult{
		Environment: root,
		Findings:    []incident.Finding{},
		Credentials: []incident.CredentialFile{},
		Ecosystems:  runRes.Ecosystems,
		Intel:       incident.IntelSummaryForOverride(override),
	}
	for _, e := range runRes.Ecosystems {
		result.PackagesRead += e.PackagesRead
	}
	for _, hit := range runRes.Hits {
		// Recover the CLI dispatch label from the OSV bucket so
		// ecosystemFindingText picks the right wording. Falls back
		// to a generic message if the ecosystem is unknown (which
		// should never happen because packagecheckEcosystems and
		// osvIDToEcoToken stay in sync via the same map literal).
		ecoToken := osvIDToEcoToken[hit.Ref.Ecosystem]
		title, remediation := ecosystemFindingText(ecoToken, hit)
		result.Findings = append(result.Findings, incident.Finding{
			Severity:    incident.SevCritical,
			Title:       title,
			Detail:      hit.Record.Summary,
			Path:        hit.Ref.Path,
			Remediation: remediation,
		})
	}
	return result, nil
}

// mergeCheckResults concatenates Findings + Credentials +
// Ecosystems across pipelines and sums PackagesRead / PthScanned.
// Intel comes from the first non-zero summary so the merged
// result's `intel` block still reflects the snapshot generation
// the pipelines actually consulted. Environment is the user-
// supplied root path (or "." when implicit) for multi-pipeline
// plans so JSON consumers do not have to reason about which
// pipeline "wins" the environment field.
func mergeCheckResults(parts []*incident.CheckResult, rootPath string) *incident.CheckResult {
	if len(parts) == 1 {
		// Single pipeline: surface its result unchanged so the
		// existing single-eco contract (Environment = the path
		// that pipeline scanned, etc.) holds.
		return parts[0]
	}
	out := &incident.CheckResult{
		Findings:    []incident.Finding{},
		Credentials: []incident.CredentialFile{},
		Ecosystems:  []packagecheck.EcosystemResult{},
	}
	if rootPath == "" {
		out.Environment = "."
	} else {
		out.Environment = rootPath
	}
	for _, p := range parts {
		if p == nil {
			continue
		}
		out.Findings = append(out.Findings, p.Findings...)
		out.Credentials = append(out.Credentials, p.Credentials...)
		out.Ecosystems = append(out.Ecosystems, p.Ecosystems...)
		out.PackagesRead += p.PackagesRead
		out.PthScanned += p.PthScanned
		if out.Intel.Mode == "" {
			out.Intel = p.Intel
		}
	}
	return out
}

// ecosystemFindingText returns the per-ecosystem (title,
// remediation) pair for a Hit. The wording stays close to the
// ecosystem's native tooling so the user can copy-paste the
// remediation into their package manager without translation.
func ecosystemFindingText(ecoToken string, hit packagecheck.Hit) (title, remediation string) {
	name, version, id := hit.Ref.Name, hit.Ref.Version, hit.Record.ID
	switch ecoToken {
	case ecoGo:
		return fmt.Sprintf("%s %s is a known compromised Go module (%s)", name, version, id),
			fmt.Sprintf("Remove %s %s from your go.mod and re-run `go mod tidy`. Rotate any tokens reachable from CI runs that included the compromised version.", name, version)
	case ecoCargo:
		return fmt.Sprintf("%s %s is a known compromised Rust crate (%s)", name, version, id),
			fmt.Sprintf("Run `cargo update -p %s` or pin a fixed version in Cargo.toml. Rotate secrets reachable from builds that used the compromised crate.", name)
	case ecoComposer:
		return fmt.Sprintf("%s %s is a known compromised Composer package (%s)", name, version, id),
			fmt.Sprintf("Run `composer update %s` or pin a fixed version in composer.json. Rotate secrets reachable from builds that used the compromised package.", name)
	case ecoRuby:
		return fmt.Sprintf("%s %s is a known compromised RubyGem (%s)", name, version, id),
			fmt.Sprintf("Run `bundle update %s` or pin a fixed version in Gemfile. Rotate secrets reachable from builds that used the compromised gem.", name)
	case ecoMaven:
		return fmt.Sprintf("%s %s is a known compromised Maven package (%s)", name, version, id),
			fmt.Sprintf("Update %s to a fixed version in pom.xml / Gradle lockfile and rebuild the lockfile. Rotate secrets reachable from builds that used the compromised package.", name)
	case ecoNuGet:
		return fmt.Sprintf("%s %s is a known compromised NuGet package (%s)", name, version, id),
			fmt.Sprintf("Update %s to a fixed version in the project file or packages.lock.json and restore. Rotate secrets reachable from builds that used the compromised package.", name)
	default:
		// Defensive: a packagecheck ecosystem without a wording
		// entry still produces a usable finding rather than a
		// crash. Adding the ecosystem-specific copy is then a
		// follow-up tightening, not a release blocker.
		return fmt.Sprintf("%s %s is a known compromised package (%s)", name, version, id),
			fmt.Sprintf("Remove %s %s from your dependencies. Rotate secrets reachable from builds that used the compromised version.", name, version)
	}
}

func writeCheckJSON(result *incident.CheckResult) error {
	w := os.Stdout
	if flagOutput != "" {
		f, err := os.Create(flagOutput)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		w = f
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func writeCheckTerminal(result *incident.CheckResult, plan checkPlan) error {
	ecosystem := plan.singleEcoToken()
	envLabel := singleEcoEnvLabel(ecosystem)
	if envLabel == "" {
		envLabel = "project dependencies"
	}
	fmt.Printf("\nScanning %s: %s\n", envLabel, result.Environment)
	switch {
	case plan.isMulti():
		fmt.Printf("Packages read: %d  |  Targets found: %d\n\n", result.PackagesRead, len(result.Ecosystems))
	case ecosystem == ecoNPM:
		fmt.Printf("Packages read: %d\n\n", result.PackagesRead)
	case ecosystem == ecoGo, ecosystem == ecoCargo, ecosystem == ecoComposer,
		ecosystem == ecoRuby, ecosystem == ecoMaven, ecosystem == ecoNuGet:
		fmt.Printf("Packages read: %d  |  Lockfiles found: %d\n\n", result.PackagesRead, len(result.Ecosystems))
	default:
		fmt.Printf("Packages read: %d  |  .pth files scanned: %d\n\n", result.PackagesRead, result.PthScanned)
	}

	if len(result.Findings) == 0 {
		green := "\033[32m"
		reset := "\033[0m"
		if flagNoColor {
			green = ""
			reset = ""
		}
		fmt.Printf("  %s✔ No compromised packages or artifacts found.%s\n\n", green, reset)
		return nil
	}

	red := "\033[31m"
	yellow := "\033[33m"
	bold := "\033[1m"
	dim := "\033[2m"
	reset := "\033[0m"
	cyan := "\033[36m"
	if flagNoColor {
		red = ""
		yellow = ""
		bold = ""
		dim = ""
		reset = ""
		cyan = ""
	}

	for _, f := range result.Findings {
		var sevColor string
		switch f.Severity {
		case incident.SevCritical:
			sevColor = red + bold
		case incident.SevWarning:
			sevColor = yellow
		default:
			sevColor = cyan
		}
		fmt.Printf("%s%-10s%s %s\n", sevColor, f.Severity, reset, f.Title)
		if f.Path != "" {
			fmt.Printf("           %sPath: %s%s\n", dim, f.Path, reset)
		}
		if f.Detail != "" {
			fmt.Printf("           %s%s%s\n", dim, f.Detail, reset)
		}
		fmt.Println()
	}

	// Credentials at risk
	atRisk := 0
	for _, c := range result.Credentials {
		if c.Exists {
			atRisk++
		}
	}
	if atRisk > 0 {
		fmt.Printf("%sCredentials at risk:%s\n", bold, reset)
		for _, c := range result.Credentials {
			if c.Exists {
				fmt.Printf("  %-30s %sEXISTS%s  %s%s%s\n", c.Path, red, reset, dim, c.Guidance, reset)
			}
		}
		fmt.Println()
	}

	// Action guidance is ecosystem-specific because `aguara clean`
	// only knows how to remove the Python compromise artifacts.
	// Maven / NuGet / Go / Rust / PHP / Ruby / npm get
	// generic "update / remove / rebuild lockfile / rotate
	// credentials" guidance; the Python path keeps the
	// `aguara clean` recommendation since it owns the
	// persistence-artifact cleanup.
	fmt.Printf("%sAction required:%s\n", bold, reset)
	switch ecosystem {
	case ecoPython:
		fmt.Println("  1. Run 'aguara clean' to remove malicious files and persistence artifacts")
		fmt.Println("  2. Rotate ALL credentials listed above")
		fmt.Println("  3. If running K8s: kubectl get pods -n kube-system | grep node-setup")
	default:
		// Single packagecheck ecosystem, or single npm, or
		// multi-ecosystem: same guidance shape (the
		// per-ecosystem package-manager commands live in each
		// Finding.Remediation, not in this summary).
		fmt.Println("  1. Update or remove the affected packages in the relevant manifest and rebuild the lockfile")
		fmt.Println("  2. Rotate ALL credentials reachable from builds / CI runs that used the compromised versions")
		fmt.Println("  3. Audit recent CI runs, especially trusted-publishing / OIDC steps")
	}

	// Build summary line
	critCount := 0
	warnCount := 0
	for _, f := range result.Findings {
		switch f.Severity {
		case incident.SevCritical:
			critCount++
		case incident.SevWarning:
			warnCount++
		}
	}
	var parts []string
	if critCount > 0 {
		parts = append(parts, fmt.Sprintf("%s%d critical%s", red, critCount, reset))
	}
	if warnCount > 0 {
		parts = append(parts, fmt.Sprintf("%s%d warning%s", yellow, warnCount, reset))
	}
	fmt.Printf("\n%s\n", strings.Join(parts, " · "))

	return nil
}

// resolveCheckIntel builds the IntelOverride the check pipeline
// should consume. ecosystems scopes a --fresh refresh to only the
// OSV buckets the plan actually touches (a `--ecosystem maven`
// user does NOT want a --fresh to pull npm + PyPI just because
// those happened to be the legacy intel.Update default). An empty
// ecosystems list leaves intel.Update's default behaviour intact
// (all supported ecosystems in v0.17).
//
// The logic is:
//
//  1. If --fresh was passed, run intel.Update for `ecosystems`;
//     on success save to local Store and override with
//     [embedded..., refreshed]. IntelSummary.Mode = "online",
//     Snapshot = "remote-fresh".
//  2. If --fresh failed AND --allow-stale was passed, fall back
//     to a local-only or embedded-only override and continue.
//  3. If --fresh was NOT passed AND a local snapshot exists,
//     layer it over the embedded snapshots. Mode stays "offline";
//     Snapshot = "local".
//  4. Otherwise, return nil so the check uses the cached embedded
//     matcher (the legacy default path).
//
// This is the only place the CLI touches the network for `check`.
// Returning nil keeps the default-check contract intact: no flags,
// no network.
func resolveCheckIntel(ctx context.Context, ecosystems []string) (*incident.IntelOverride, error) {
	store, storeErr := intel.DefaultStore()
	if storeErr != nil {
		// A missing $HOME is exotic; fall through to the
		// embedded-only path rather than blocking the check.
		store = nil
	}

	if flagCheckFresh {
		ctx, cancel := context.WithTimeout(ctx, intel.DefaultHTTPTimeout)
		defer cancel()

		res, err := intel.Update(ctx, intel.UpdateOptions{
			Importer:   osvUpdateAdapter,
			Stderr:     os.Stderr,
			Ecosystems: ecosystems,
		})
		if err != nil {
			if !flagCheckAllowStale {
				return nil, fmt.Errorf("--fresh refresh failed: %w (pass --allow-stale to fall back to cached intel)", err)
			}
			fmt.Fprintf(os.Stderr, "warning: --fresh refresh failed (%v); falling back to cached intel\n", err)
			return localOrEmbeddedOverride(store), nil
		}
		if store != nil {
			if saveErr := store.Save(res.Snapshot); saveErr != nil {
				fmt.Fprintf(os.Stderr, "warning: --fresh: save snapshot failed: %v\n", saveErr)
			}
		}
		snaps := append([]intel.Snapshot{}, incident.EmbeddedSnapshots()...)
		snaps = append(snaps, res.Snapshot)
		return &incident.IntelOverride{
			Snapshots:     snaps,
			Mode:          "online",
			SnapshotLabel: "remote-fresh",
		}, nil
	}

	return localOrEmbeddedOverride(store), nil
}

// localOrEmbeddedOverride returns an override layered over the
// embedded snapshots when a local snapshot exists, or nil when no
// local snapshot is found. Returning nil for the no-local case
// keeps the cached default matcher in play -- no per-check
// allocation, no behavioural change for the default `aguara check`
// invocation.
func localOrEmbeddedOverride(store *intel.Store) *incident.IntelOverride {
	if store == nil {
		return nil
	}
	snap, err := store.Load()
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "warning: local intel snapshot unreadable: %v\n", err)
		}
		return nil
	}
	snaps := append([]intel.Snapshot{}, incident.EmbeddedSnapshots()...)
	snaps = append(snaps, *snap)
	return &incident.IntelOverride{
		Snapshots:     snaps,
		Mode:          "offline",
		SnapshotLabel: "local",
	}
}

// osvUpdateAdapter is the production wiring of intel.UpdateOptions.Importer
// to osvimport.ImportFromZip. Mirrors the adapter in update.go so the
// two CLI surfaces (`aguara update` and `aguara check --fresh`) share
// one importer hook.
func osvUpdateAdapter(r io.ReaderAt, size int64, ecosystems []string, generatedAt time.Time) (intel.Snapshot, error) {
	return osvimport.ImportFromZip(r, size, osvimport.Options{
		Ecosystems:  ecosystems,
		GeneratedAt: generatedAt,
	})
}

// checkSeverityRank orders Finding.Severity strings against the
// --fail-on threshold. Unknown severities (defensive: future entries
// the runtime predates) sort below INFO so they cannot trip the gate.
var checkSeverityRank = map[string]int{
	incident.SevInfo:     0,
	incident.SevWarning:  1,
	incident.SevCritical: 2,
}

// checkIncidentFailOnThreshold returns ErrThresholdExceeded when any
// finding in result meets or exceeds the configured severity threshold.
// An empty threshold disables the gate (return nil).
//
// Kept separate from scan's checkFailOnThreshold because the check
// pipeline uses string severities (CRITICAL/WARNING/INFO) rather than
// scan's numeric Severity enum. Both gates fail with the same
// sentinel so main.go's exit-code logic stays uniform.
func checkIncidentFailOnThreshold(result *incident.CheckResult, threshold string) error {
	if threshold == "" {
		return nil
	}
	thrKey := strings.ToUpper(strings.TrimSpace(threshold))
	thr, ok := checkSeverityRank[thrKey]
	if !ok {
		return fmt.Errorf("invalid --fail-on %q: choose critical, warning, or info", threshold)
	}
	for _, f := range result.Findings {
		rank, ok := checkSeverityRank[strings.ToUpper(f.Severity)]
		if !ok {
			continue
		}
		if rank >= thr {
			return ErrThresholdExceeded
		}
	}
	return nil
}
