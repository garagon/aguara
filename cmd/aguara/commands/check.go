package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/garagon/aguara/internal/incident"
	"github.com/spf13/cobra"
)

var (
	flagCheckPath      string
	flagCheckEcosystem string
	flagCheckFailOn    string
	flagCheckCI        bool
)

const (
	ecoPython = "python"
	ecoNPM    = "npm"
)

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check for compromised packages and persistence artifacts",
	Long: `Scan an installed package tree for known compromised versions and
persistence artifacts. With no flags, auto-detects an npm project (any
directory containing node_modules) and otherwise falls back to Python
site-packages discovery. Pass --ecosystem to force a specific check.
The known-bad list ships embedded with the binary.`,
	RunE: runCheck,
}

func init() {
	checkCmd.Flags().StringVar(&flagCheckPath, "path", "", "Path to project root, node_modules, or Python site-packages")
	checkCmd.Flags().StringVar(&flagCheckEcosystem, "ecosystem", "", "Package ecosystem (auto-detect by default): python or npm")
	checkCmd.Flags().StringVar(&flagCheckFailOn, "fail-on", "", "Exit with code 1 if findings reach this severity: critical, warning, info")
	checkCmd.Flags().BoolVar(&flagCheckCI, "ci", false, "CI mode: equivalent to --fail-on critical --no-color")
	rootCmd.AddCommand(checkCmd)
}

func runCheck(cmd *cobra.Command, args []string) error {
	applyCheckCIDefaults()

	eco, path, err := resolveCheckTarget(flagCheckEcosystem, flagCheckPath)
	if err != nil {
		return err
	}

	opts := incident.CheckOptions{Path: path}
	var result *incident.CheckResult
	switch eco {
	case ecoPython:
		result, err = incident.Check(opts)
	case ecoNPM:
		result, err = incident.CheckNPM(opts)
	default:
		return fmt.Errorf("internal error: unresolved ecosystem %q", eco)
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
func resolveCheckTarget(eco, path string) (string, string, error) {
	switch strings.ToLower(strings.TrimSpace(eco)) {
	case "python", "pypi":
		return ecoPython, path, nil
	case "npm":
		return ecoNPM, path, nil
	case "":
		return autoDetectCheckTarget(path)
	default:
		return "", "", fmt.Errorf("unsupported ecosystem %q: choose python or npm", eco)
	}
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
	}
	// Fall back to Python. Preserve the caller's original (possibly
	// empty) path so discoverSitePackages() can still kick in.
	return ecoPython, path, nil
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
	if ecosystem == ecoNPM {
		envLabel = "npm node_modules tree"
	}
	fmt.Printf("\nScanning %s: %s\n", envLabel, result.Environment)
	if ecosystem == ecoNPM {
		fmt.Printf("Packages read: %d\n\n", result.PackagesRead)
	} else {
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
