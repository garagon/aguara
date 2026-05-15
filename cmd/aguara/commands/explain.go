package commands

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/garagon/aguara/internal/rulecatalog"
	"github.com/garagon/aguara/internal/rulemeta"
)

var explainCmd = &cobra.Command{
	Use:   "explain <RULE_ID>",
	Short: "Show detailed information about a detection rule",
	Args:  cobra.ExactArgs(1),
	RunE:  runExplain,
}

func init() {
	// `rule not found` is a runtime user error (typo in the ID),
	// not a flag-parse issue. Cobra's default behaviour would
	// dump the Usage block on top of the error -- in CI logs that
	// reads as command misuse rather than "you typed the ID
	// wrong". Same SilenceUsage pattern PR #91 applied to scan /
	// check / audit / update.
	explainCmd.SilenceUsage = true
	rootCmd.AddCommand(explainCmd)
}

func runExplain(cmd *cobra.Command, args []string) error {
	ruleID := strings.ToUpper(strings.TrimSpace(args[0]))

	found, err := rulecatalog.FindByID(rulecatalog.Options{
		CustomRulesDir: flagRules,
		Warn: func(format string, a ...any) {
			fmt.Fprintf(cmd.ErrOrStderr(), format, a...)
		},
	}, ruleID)
	if err != nil {
		// Distinguish a clean miss (typo in the ID) from a
		// catalog-build failure (e.g. --rules points at a
		// missing directory). The latter must surface its real
		// error so the user can diagnose, not get masked as
		// "rule not found".
		if errors.Is(err, rulecatalog.ErrRuleNotFound) {
			return fmt.Errorf("rule %q not found", ruleID)
		}
		return err
	}

	w := cmd.OutOrStdout()
	if strings.ToLower(flagFormat) == "json" {
		return writeExplainJSON(w, found)
	}
	return writeExplainTerminal(w, found)
}

func writeExplainJSON(w io.Writer, r *rulemeta.Rule) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func writeExplainTerminal(w io.Writer, found *rulemeta.Rule) error {
	color := func(code, text string) string {
		if flagNoColor {
			return text
		}
		return code + text + "\033[0m"
	}

	bold := "\033[1m"
	dim := "\033[2m"
	yellow := "\033[33m"
	cyan := "\033[36m"
	red := "\033[31m"
	green := "\033[32m"

	sevColor := cyan
	switch found.Severity {
	case "CRITICAL":
		sevColor = red + bold
	case "HIGH":
		sevColor = red
	case "MEDIUM":
		sevColor = yellow
	}

	fmt.Fprintf(w, "\n%s %s\n", color(dim, "Rule:"), color(bold, found.ID))
	fmt.Fprintf(w, "%s %s\n", color(dim, "Name:"), found.Name)
	fmt.Fprintf(w, "%s %s\n", color(dim, "Severity:"), color(sevColor, found.Severity))
	fmt.Fprintf(w, "%s %s\n", color(dim, "Category:"), found.Category)
	if found.Analyzer != "" {
		fmt.Fprintf(w, "%s %s\n", color(dim, "Analyzer:"), found.Analyzer)
	}

	if found.Description != "" {
		fmt.Fprintf(w, "\n%s\n%s\n", color(bold, "Description:"), found.Description)
	}

	if found.Remediation != "" {
		fmt.Fprintf(w, "\n%s\n%s\n", color(bold, "Remediation:"), color(green, found.Remediation))
	}

	if len(found.Patterns) > 0 {
		fmt.Fprintf(w, "\n%s\n", color(bold, "Patterns:"))
		for i, p := range found.Patterns {
			fmt.Fprintf(w, "  %d. %s\n", i+1, color(dim, p))
		}
	}

	if len(found.TruePositives) > 0 {
		fmt.Fprintf(w, "\n%s\n", color(bold, "True Positives:"))
		for _, ex := range found.TruePositives {
			fmt.Fprintf(w, "  %s %s\n", color(red, "✖"), ex)
		}
	}

	if len(found.FalsePositives) > 0 {
		fmt.Fprintf(w, "\n%s\n", color(bold, "False Positives:"))
		for _, ex := range found.FalsePositives {
			fmt.Fprintf(w, "  %s %s\n", color(green, "✔"), ex)
		}
	}

	fmt.Fprintln(w)
	return nil
}
