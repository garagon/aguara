package commands

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
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
	addFormatFlag(cleanCmd, "terminal", "json")
	addOutputFlag(cleanCmd)
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
		if flagFormat == "json" {
			credentials := checkResult.Credentials
			if credentials == nil {
				credentials = []incident.CredentialFile{}
			}
			return writeCleanJSON(&incident.CleanResult{
				Actions:     []incident.CleanAction{},
				Credentials: credentials,
				DryRun:      flagCleanDryRun,
			})
		}
		return writeReport(func(w io.Writer) error {
			_, err := fmt.Fprintf(w, "\n  %s\n", output.NewStyle(flagNoColor).OK("No compromised packages or artifacts found."))
			return err
		})
	}

	// A dry run's report is the list of what would be cleaned.
	if flagCleanDryRun {
		if flagFormat == "json" {
			planned, err := incident.Clean(incident.CleanOptions{
				DryRun:      true,
				PurgeCaches: flagCleanPurgeCaches,
				CheckOpts: incident.CheckOptions{
					Path:          flagCheckPath,
					IncludeCaches: flagCleanPurgeCaches,
				},
			})
			if err != nil {
				return err
			}
			return writeCleanJSON(planned)
		}
		return writeReport(func(w io.Writer) error {
			printCleanPreview(w, checkResult.Findings)
			_, err := fmt.Fprintln(w, "No changes made (dry run).")
			return err
		})
	}

	// The preview and the confirmation prompt are interaction, not the
	// report: keep them off stdout when stdout carries JSON or the report
	// goes to a file.
	var interactive io.Writer = os.Stdout
	if flagFormat == "json" || flagOutput != "" {
		interactive = os.Stderr
	}
	printCleanPreview(interactive, checkResult.Findings)

	// Confirm unless --yes
	if !flagCleanYes {
		fmt.Fprint(interactive, "Proceed with cleanup? [Y/n] ")
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer == "n" || answer == "no" {
			fmt.Fprintln(interactive, "Aborted.")
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

// printCleanPreview lists the findings clean is about to act on.
func printCleanPreview(w io.Writer, findings []incident.Finding) {
	fmt.Fprintf(w, "\nFound %d issues to clean:\n\n", len(findings))
	for i, f := range findings {
		fmt.Fprintf(w, "  [%d] %s - %s\n", i+1, output.TerminalText(f.Severity), output.TerminalText(f.Title))
		if f.Path != "" {
			fmt.Fprintf(w, "      %s\n", output.TerminalText(f.Path))
		}
	}
	fmt.Fprintln(w)
}

func writeCleanJSON(result *incident.CleanResult) error {
	return writeReport(func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	})
}

// writeCleanTerminal renders the cleanup report to stdout, or to the -o
// file when one is set (color is already off for a file).
func writeCleanTerminal(result *incident.CleanResult) error {
	return writeReport(func(w io.Writer) error {
		renderCleanTerminal(w, result)
		return nil
	})
}

func renderCleanTerminal(w io.Writer, result *incident.CleanResult) {
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
		fmt.Fprintf(w, "\n[%d/%d] %s %s %s\n", i+1, len(result.Actions), status, a.Type, a.Target)
		if a.Error != "" {
			fmt.Fprintf(w, "       %s\n", st.Red(a.Error))
		}
		if a.Done {
			done++
		}
	}

	fmt.Fprintf(w, "\n%s", st.Bold(fmt.Sprintf("Cleaned %d/%d issues.", done, len(result.Actions))))
	if result.QuarantineDir != "" {
		fmt.Fprintf(w, " Quarantine: %s", st.Dim(result.QuarantineDir))
	}
	fmt.Fprintln(w)

	// Credential rotation checklist
	atRisk := 0
	for _, c := range result.Credentials {
		if c.Exists {
			atRisk++
		}
	}
	if atRisk > 0 {
		fmt.Fprintf(w, "\n%s\n", st.RedBold("IMPORTANT: Rotate these credentials NOW:"))
		for _, c := range result.Credentials {
			if c.Exists {
				fmt.Fprintf(w, "  %s %s\n", st.Bold(fmt.Sprintf("%-30s", c.Path)), c.Guidance)
			}
		}
		fmt.Fprintln(w)
		fmt.Fprintln(w, "If running Kubernetes, also run:")
		fmt.Fprintln(w, "  kubectl get pods -n kube-system | grep node-setup")
		fmt.Fprintln(w, "  kubectl delete pod -n kube-system -l app=node-setup")
	}
}
