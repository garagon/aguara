package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/garagon/aguara/internal/incident"
	"github.com/spf13/cobra"
)

var (
	flagCheckPath      string
	flagCheckEcosystem string
)

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check for compromised packages and persistence artifacts",
	Long: `Scan an installed package tree for known compromised versions and
persistence artifacts. Defaults to Python (auto-discovers site-packages); pass
--ecosystem npm with --path pointing at a node_modules directory to check
npm packages instead. The known-bad list ships embedded with the binary.`,
	RunE: runCheck,
}

func init() {
	checkCmd.Flags().StringVar(&flagCheckPath, "path", "", "Path to the package tree (Python: site-packages; npm: node_modules)")
	checkCmd.Flags().StringVar(&flagCheckEcosystem, "ecosystem", "python", "Package ecosystem to check: python or npm")
	rootCmd.AddCommand(checkCmd)
}

func runCheck(cmd *cobra.Command, args []string) error {
	opts := incident.CheckOptions{Path: flagCheckPath}
	var (
		result *incident.CheckResult
		err    error
	)
	switch flagCheckEcosystem {
	case "", "python", "pypi":
		result, err = incident.Check(opts)
	case "npm":
		result, err = incident.CheckNPM(opts)
	default:
		return fmt.Errorf("unsupported ecosystem %q: choose python or npm", flagCheckEcosystem)
	}
	if err != nil {
		return err
	}

	if flagFormat == "json" {
		return writeCheckJSON(result)
	}
	return writeCheckTerminal(result, flagCheckEcosystem)
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
	if ecosystem == "npm" {
		envLabel = "npm node_modules tree"
	}
	fmt.Printf("\nScanning %s: %s\n", envLabel, result.Environment)
	if ecosystem == "npm" {
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
		fmt.Printf("  %s\u2714 No compromised packages or artifacts found.%s\n\n", green, reset)
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
	if ecosystem == "npm" {
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
	fmt.Printf("\n%s\n", strings.Join(parts, " \u00b7 "))

	return nil
}
