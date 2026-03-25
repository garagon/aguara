package commands

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/garagon/aguara/internal/incident"
	"github.com/spf13/cobra"
)

var (
	flagCleanDryRun      bool
	flagCleanPurgeCaches bool
	flagCleanYes         bool
)

var cleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Remove compromised packages, malicious files, and persistence artifacts",
	Long: `Detects and removes compromised Python packages, quarantines malicious .pth files,
and disables persistence backdoors. Use --dry-run to preview without changes.`,
	RunE: runClean,
}

func init() {
	cleanCmd.Flags().BoolVar(&flagCleanDryRun, "dry-run", false, "Show what would be removed without making changes")
	cleanCmd.Flags().BoolVar(&flagCleanPurgeCaches, "purge-caches", false, "Also purge pip/uv package caches")
	cleanCmd.Flags().BoolVar(&flagCleanYes, "yes", false, "Skip confirmation prompt")
	rootCmd.AddCommand(cleanCmd)
}

func runClean(cmd *cobra.Command, args []string) error {
	// First run check to see what we're dealing with
	checkResult, err := incident.Check(incident.CheckOptions{
		Path:          flagCheckPath,
		IncludeCaches: flagCleanPurgeCaches,
	})
	if err != nil {
		return err
	}

	if len(checkResult.Findings) == 0 {
		fmt.Println("\n  \033[32m\u2714 No compromised packages or artifacts found.\033[0m")
		return nil
	}

	// Show what was found
	fmt.Printf("\nFound %d issues to clean:\n\n", len(checkResult.Findings))
	for i, f := range checkResult.Findings {
		fmt.Printf("  [%d] %s - %s\n", i+1, f.Severity, f.Title)
		if f.Path != "" {
			fmt.Printf("      %s\n", f.Path)
		}
	}
	fmt.Println()

	if flagCleanDryRun {
		fmt.Println("No changes made (dry run).")
		return nil
	}

	// Confirm unless --yes
	if !flagCleanYes {
		fmt.Print("Proceed with cleanup? [Y/n] ")
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer == "n" || answer == "no" {
			fmt.Println("Aborted.")
			return nil
		}
	}

	// Run cleanup
	result, err := incident.Clean(incident.CleanOptions{
		DryRun:      false,
		PurgeCaches: flagCleanPurgeCaches,
		CheckOpts: incident.CheckOptions{
			Path:          flagCheckPath,
			IncludeCaches: flagCleanPurgeCaches,
		},
	})
	if err != nil {
		return err
	}

	if flagFormat == "json" {
		return writeCleanJSON(result)
	}
	return writeCleanTerminal(result)
}

func writeCleanJSON(result *incident.CleanResult) error {
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

func writeCleanTerminal(result *incident.CleanResult) error {
	red := "\033[31m"
	green := "\033[32m"
	bold := "\033[1m"
	dim := "\033[2m"
	reset := "\033[0m"
	if flagNoColor {
		red = ""
		green = ""
		bold = ""
		dim = ""
		reset = ""
	}

	done := 0
	for i, a := range result.Actions {
		status := green + "\u2714" + reset
		if a.Error != "" {
			status = red + "\u2716" + reset
		}
		if !a.Done && a.Error == "" {
			status = dim + "-" + reset
		}
		fmt.Printf("\n[%d/%d] %s %s %s\n", i+1, len(result.Actions), status, a.Type, a.Target)
		if a.Error != "" {
			fmt.Printf("       %s%s%s\n", red, a.Error, reset)
		}
		if a.Done {
			done++
		}
	}

	fmt.Printf("\n%sCleaned %d/%d issues.%s", bold, done, len(result.Actions), reset)
	if result.QuarantineDir != "" {
		fmt.Printf(" Quarantine: %s%s%s", dim, result.QuarantineDir, reset)
	}
	fmt.Println()

	// Credential rotation checklist
	atRisk := 0
	for _, c := range result.Credentials {
		if c.Exists {
			atRisk++
		}
	}
	if atRisk > 0 {
		fmt.Printf("\n%sIMPORTANT: Rotate these credentials NOW:%s\n", bold+red, reset)
		for _, c := range result.Credentials {
			if c.Exists {
				fmt.Printf("  %s%-30s%s %s\n", bold, c.Path, reset, c.Guidance)
			}
		}
		fmt.Println()
		fmt.Println("If running Kubernetes, also run:")
		fmt.Println("  kubectl get pods -n kube-system | grep node-setup")
		fmt.Println("  kubectl delete pod -n kube-system -l app=node-setup")
	}

	return nil
}
