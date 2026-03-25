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
	flagCheckPath string
)

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check for compromised Python packages and persistence artifacts",
	Long: `Scan installed Python packages for known compromised versions, malicious .pth
files, persistence backdoors, and pip/uv/npx caches. Reports which credential files are at risk.`,
	RunE: runCheck,
}

func init() {
	checkCmd.Flags().StringVar(&flagCheckPath, "path", "", "Path to site-packages directory (default: auto-discover)")
	rootCmd.AddCommand(checkCmd)
}

func runCheck(cmd *cobra.Command, args []string) error {
	result, err := incident.Check(incident.CheckOptions{
		Path: flagCheckPath,
	})
	if err != nil {
		return err
	}

	if flagFormat == "json" {
		return writeCheckJSON(result)
	}
	return writeCheckTerminal(result)
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

func writeCheckTerminal(result *incident.CheckResult) error {
	fmt.Printf("\nScanning Python environment: %s\n", result.Environment)
	fmt.Printf("Packages read: %d  |  .pth files scanned: %d\n\n", result.PackagesRead, result.PthScanned)

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

	// Action guidance
	fmt.Printf("%sAction required:%s\n", bold, reset)
	fmt.Println("  1. Run 'aguara clean' to remove malicious files")
	fmt.Println("  2. Rotate ALL credentials listed above")
	fmt.Println("  3. If running K8s: kubectl get pods -n kube-system | grep node-setup")

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
