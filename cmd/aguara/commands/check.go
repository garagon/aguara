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
	flagCheckPath       string
	flagCheckEcosystem  string
	flagCheckFailOn     string
	flagCheckCI         bool
	flagCheckFresh      bool
	flagCheckAllowStale bool
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

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check for compromised packages and persistence artifacts",
	Long: `Scan an installed package tree for known compromised versions and
persistence artifacts. With no flags, auto-detects npm (any directory
containing node_modules), Go (go.sum or go.mod at the path root), or
falls back to Python site-packages discovery. Pass --ecosystem to force
a specific check:

  python (alias: pypi)
  npm
  go     (alias: golang)
  cargo  (alias: rust)
  composer (alias: php)
  ruby   (aliases: gem, rubygems)
  maven  (alias: java)
  nuget  (aliases: dotnet, csharp)

The known-bad list ships embedded with the binary.`,
	RunE: runCheck,
}

func init() {
	checkCmd.Flags().StringVar(&flagCheckPath, "path", "", "Path to project root, node_modules, or Python site-packages")
	checkCmd.Flags().StringVar(&flagCheckEcosystem, "ecosystem", "", "Package ecosystem (auto-detect by default): python, npm, go, cargo, composer, ruby, maven, nuget")
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

	eco, path, err := resolveCheckTarget(flagCheckEcosystem, flagCheckPath)
	if err != nil {
		return err
	}

	override, err := resolveCheckIntel(cmd.Context())
	if err != nil {
		return err
	}

	opts := incident.CheckOptions{Path: path, Intel: override}
	var result *incident.CheckResult
	switch eco {
	case ecoPython:
		result, err = incident.Check(opts)
	case ecoNPM:
		result, err = incident.CheckNPM(opts)
	default:
		osvID, ok := packagecheckEcosystems[eco]
		if !ok {
			return fmt.Errorf("internal error: unresolved ecosystem %q", eco)
		}
		result, err = runPackageCheck(path, osvID, eco, override)
	}
	if err != nil {
		return err
	}

	if flagFormat == "json" {
		if err := writeCheckJSON(result); err != nil {
			return err
		}
	} else {
		if err := writeCheckTerminal(result, eco); err != nil {
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

// resolveCheckTarget turns the user-supplied --ecosystem / --path pair
// into a (resolved-ecosystem, path) tuple the runner can dispatch on.
//
// Explicit --ecosystem values short-circuit auto-detection; only when
// --ecosystem is empty does auto-detection run. An empty --path remains
// empty for Python (so the legacy site-packages auto-discovery still
// works) and resolves to "." for npm probing only.
//
// An EXPLICIT --path that does not exist (or points at a regular file)
// is an error: a typo in CI -- e.g. `--path /opt/venv/lib/pyhton...` --
// must not look like a clean check result. The validator only fires
// when path != ""; empty path keeps the legacy Python autodiscovery
// contract intact.
func resolveCheckTarget(eco, path string) (string, string, error) {
	if err := validateExplicitCheckPath(path); err != nil {
		return "", "", err
	}
	switch strings.ToLower(strings.TrimSpace(eco)) {
	case "python", "pypi":
		return ecoPython, path, nil
	case "npm":
		return ecoNPM, path, nil
	case "go", "golang":
		return ecoGo, path, nil
	case "cargo", "rust":
		return ecoCargo, path, nil
	case "composer", "php":
		return ecoComposer, path, nil
	case "ruby", "gem", "rubygems":
		return ecoRuby, path, nil
	case "maven", "java":
		return ecoMaven, path, nil
	case "nuget", "dotnet", "csharp":
		return ecoNuGet, path, nil
	case "":
		return autoDetectCheckTarget(path)
	default:
		return "", "", fmt.Errorf("unsupported ecosystem %q: choose python, npm, go, cargo, composer, ruby, maven, or nuget", eco)
	}
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

// autoDetectCheckTarget chooses an ecosystem from the filesystem shape
// at path. The rules are deliberately narrow so the default
// `aguara check` does not silently switch ecosystems on directories
// that merely happen to share a name with one. npm wins only when
// there is a real node_modules directory; otherwise the call falls
// back to the historical Python check path.
func autoDetectCheckTarget(path string) (string, string, error) {
	probe := path
	if probe == "" {
		probe = "."
	}
	if info, err := os.Stat(probe); err == nil && info.IsDir() {
		// Resolve the probe so `filepath.Base` returns the real
		// directory name. Without this, `aguara check` from inside
		// a node_modules tree (probe == ".") would yield Base == "."
		// and the npm signal would be missed -- the npm checker
		// never runs and a compromised package is silently reported
		// clean. Fall back to the raw probe if Abs fails, so we
		// still get the historical behaviour on weird inputs.
		resolved := probe
		if abs, err := filepath.Abs(probe); err == nil {
			resolved = abs
		}
		// On the npm-detected branches, return the resolved path so
		// incident.CheckNPM -> resolveNPMRoot does not have to repeat
		// the same dot-aware basename trick. Passing a literal "."
		// through here breaks the npm walker because
		// filepath.Base(".") == "." and the path has no
		// `./node_modules` child.
		if filepath.Base(resolved) == "node_modules" {
			return ecoNPM, resolved, nil
		}
		nm := filepath.Join(resolved, "node_modules")
		if nmInfo, err := os.Stat(nm); err == nil && nmInfo.IsDir() {
			return ecoNPM, resolved, nil
		}
		// PR #2: Go autodetect. If go.sum or go.mod sits at the
		// probe root we treat the directory as a Go module and run
		// the packagecheck Go path. The check is intentionally
		// shallow (only the probe root, not a recursive walk) so a
		// vendored go.sum deep inside a Python project does not
		// silently switch ecosystems on the user. The Runner's
		// discovery walks recursively from `resolved` once the
		// dispatch lands on ecoGo.
		if statRegularFile(filepath.Join(resolved, "go.sum")) || statRegularFile(filepath.Join(resolved, "go.mod")) {
			return ecoGo, resolved, nil
		}
	}
	// Fall back to Python. Preserve the caller's original (possibly
	// empty) path so discoverSitePackages() can still kick in.
	return ecoPython, path, nil
}

// statRegularFile is the autodetect-side existence probe. Lives in
// this file (not packagecheck) because autodetect operates on the
// scan root before we know which ecosystem owns it.
func statRegularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// runPackageCheck dispatches a packagecheck-routed ecosystem
// branch of `aguara check`. Discovers every lockfile under path
// for the requested ecosystem, parses each, looks every
// (name, version) up in the matcher built from override (or the
// cached embedded default when override is nil), and emits a
// CheckResult populated with:
//
//   - Findings: one entry per matched (name, version, advisory)
//     tuple, severity CRITICAL with ecosystem-specific
//     remediation text.
//   - Ecosystems: one entry per discovered lockfile.
//   - PackagesRead: sum of declared packages across every target.
//   - Intel: the IntelSummary the override would have produced.
//
// Returns a clean CheckResult with empty Ecosystems / Findings
// when no lockfiles for the requested ecosystem are present under
// path. That is the "no targets for the requested ecosystem"
// contract the user spec asks for (zero error, just empty arrays).
//
// osvID is the canonical OSV bucket the matcher consults; ecoToken
// is the CLI-side dispatch label (ecoGo / ecoCargo / etc.) used
// only to pick the finding title and remediation text.
func runPackageCheck(path, osvID, ecoToken string, override *incident.IntelOverride) (*incident.CheckResult, error) {
	root := path
	if root == "" {
		root = "."
	}
	targets, err := packagecheck.Discover(root, []string{osvID})
	if err != nil {
		return nil, fmt.Errorf("aguara check %s: discover %s: %w", ecoToken, root, err)
	}
	runner := &packagecheck.Runner{Matcher: incident.MatcherForOverride(override)}
	runRes, err := runner.Run(targets)
	if err != nil {
		return nil, fmt.Errorf("aguara check %s: %w", ecoToken, err)
	}

	result := &incident.CheckResult{
		Environment:  root,
		Findings:     []incident.Finding{},
		Credentials:  []incident.CredentialFile{},
		PackagesRead: 0,
		Intel:        incident.IntelSummaryForOverride(override),
		Ecosystems:   runRes.Ecosystems,
	}
	for _, e := range runRes.Ecosystems {
		result.PackagesRead += e.PackagesRead
	}
	for _, hit := range runRes.Hits {
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

func writeCheckTerminal(result *incident.CheckResult, ecosystem string) error {
	envLabel := "Python environment"
	switch ecosystem {
	case ecoNPM:
		envLabel = "npm node_modules tree"
	case ecoGo:
		envLabel = "Go modules"
	case ecoCargo:
		envLabel = "Rust crates"
	case ecoComposer:
		envLabel = "Composer packages"
	case ecoRuby:
		envLabel = "RubyGems"
	case ecoMaven:
		envLabel = "Maven / Gradle dependencies"
	case ecoNuGet:
		envLabel = "NuGet packages"
	}
	fmt.Printf("\nScanning %s: %s\n", envLabel, result.Environment)
	switch ecosystem {
	case ecoNPM:
		fmt.Printf("Packages read: %d\n\n", result.PackagesRead)
	case ecoGo, ecoCargo, ecoComposer, ecoRuby, ecoMaven, ecoNuGet:
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
	fmt.Printf("%sAction required:%s\n", bold, reset)
	if ecosystem == ecoNPM {
		fmt.Println("  1. Remove the affected packages with the package manager (`npm uninstall <name>`)")
		fmt.Println("  2. Rotate ALL credentials reachable from runs that included the compromised version")
		fmt.Println("  3. Audit recent CI runs, especially trusted-publishing / OIDC steps")
	} else {
		fmt.Println("  1. Run 'aguara clean' to remove malicious files")
		fmt.Println("  2. Rotate ALL credentials listed above")
		fmt.Println("  3. If running K8s: kubectl get pods -n kube-system | grep node-setup")
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
// should consume. The logic is:
//
//  1. If --fresh was passed, run intel.Update; on success save to
//     local Store and override with [embedded..., refreshed].
//     IntelSummary.Mode = "online", Snapshot = "remote-fresh".
//  2. If --fresh failed AND --allow-stale was passed, fall back
//     to a local-only or embedded-only override and continue.
//  3. If --fresh was NOT passed AND a local snapshot exists, layer
//     it over the embedded snapshots. Mode stays "offline";
//     Snapshot = "local".
//  4. Otherwise, return nil so the check uses the cached embedded
//     matcher (the legacy default path).
//
// This is the only place the CLI touches the network for `check`.
// Returning nil keeps the default-check contract intact: no flags,
// no network.
func resolveCheckIntel(ctx context.Context) (*incident.IntelOverride, error) {
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
			Importer: osvUpdateAdapter,
			Stderr:   os.Stderr,
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
