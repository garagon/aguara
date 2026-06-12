package commands

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/garagon/aguara/internal/incident"
	"github.com/garagon/aguara/internal/output"
	"github.com/spf13/cobra"
)

var (
	flagCleanDryRun      bool
	flagCleanPurgeCaches bool
	flagCleanYes         bool
)

var cleanCmd = &cobra.Command{
	Use:     "clean",
	GroupID: groupScan,
	Short:   "Remove compromised packages, malicious files, and persistence artifacts",
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
	st := output.NewStyle(flagNoColor)

	done := 0
	for i, a := range result.Actions {
		status := st.Green("\u2714")
		if a.Error != "" {
			status = st.Red("\u2716")
		}
		if !a.Done && a.Error == "" {
			status = st.Dim("-")
		}
		fmt.Printf("\n[%d/%d] %s %s %s\n", i+1, len(result.Actions), status, a.Type, a.Target)
		if a.Error != "" {
			fmt.Printf("       %s\n", st.Red(a.Error))
		}
		if a.Done {
			done++
		}
	}

	fmt.Printf("\n%s", st.Bold(fmt.Sprintf("Cleaned %d/%d issues.", done, len(result.Actions))))
	if result.QuarantineDir != "" {
		fmt.Printf(" Quarantine: %s", st.Dim(result.QuarantineDir))
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
		fmt.Printf("\n%s\n", st.RedBold("IMPORTANT: Rotate these credentials NOW:"))
		for _, c := range result.Credentials {
			if c.Exists {
				fmt.Printf("  %s %s\n", st.Bold(fmt.Sprintf("%-30s", c.Path)), c.Guidance)
			}
		}
		fmt.Println()
		fmt.Println("If running Kubernetes, also run:")
		fmt.Println("  kubectl get pods -n kube-system | grep node-setup")
		fmt.Println("  kubectl delete pod -n kube-system -l app=node-setup")
	}

	return nil
}
