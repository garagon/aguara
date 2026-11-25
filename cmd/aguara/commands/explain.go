package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/garagon/aguara/internal/config"
	"github.com/garagon/aguara/internal/output"
	"github.com/garagon/aguara/internal/rulemeta"
)

var explainCmd = &cobra.Command{
	Use:     "explain <RULE_ID>",
	GroupID: groupRules,
	Short:   "Show detailed information about a detection rule",
	Args:    cobra.ExactArgs(1),
	RunE:    runExplain,
}

func init() {
	// `rule not found` is a runtime user error (typo in the ID),
	// not a flag-parse issue. Cobra's default behaviour would
	// dump the Usage block on top of the error -- in CI logs that
	// reads as command misuse rather than "you typed the ID
	// wrong". Same SilenceUsage pattern PR #91 applied to scan /
	// check / audit / update.
	explainCmd.SilenceUsage = true
	addFormatFlag(explainCmd, "terminal", "json")
	addOutputFlag(explainCmd)
	addRulesFlag(explainCmd)
	rootCmd.AddCommand(explainCmd)
}

func runExplain(cmd *cobra.Command, args []string) error {
	ruleID := strings.ToUpper(strings.TrimSpace(args[0]))

	// A catalog-build failure (e.g. --rules points at a missing directory
	// or holds a rule that does not compile) surfaces its real error so
	// the user can diagnose it, instead of being masked as "rule not
	// found". explain does not apply --disable-rule.
	res, err := resolveCLIRules(config.Config{}, nil, cmd.ErrOrStderr())
	if err != nil {
		return err
	}
	var found *rulemeta.Rule
	for _, r := range res.Catalog("") {
		if strings.EqualFold(r.ID, ruleID) {
			found = &r
			break
		}
	}
	if found == nil {
		return fmt.Errorf("rule %q not found", ruleID)
	}

	return writeCommandReport(cmd, func(w io.Writer) error {
		if strings.ToLower(flagFormat) == "json" {
			return writeExplainJSON(w, found)
		}
		return writeExplainTerminal(w, found)
	})
}

func writeExplainJSON(w io.Writer, r *rulemeta.Rule) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func writeExplainTerminal(w io.Writer, found *rulemeta.Rule) error {
	st := output.NewStyle(flagNoColor)

	fmt.Fprintf(w, "\n%s %s %s %s\n", st.SeverityIcon(found.Severity), st.Bold(found.ID), found.Name, st.SeverityLabel(found.Severity))
	fmt.Fprintf(w, "%s %s\n", st.Dim("Category:"), found.Category)
	fmt.Fprintf(w, "%s %s\n", st.Dim("Decision impact:"), found.DecisionImpact)
	if found.Analyzer != "" {
		fmt.Fprintf(w, "%s %s\n", st.Dim("Analyzer:"), found.Analyzer)
	}

	if found.Description != "" {
		fmt.Fprintf(w, "\n%s\n%s\n", st.Bold("Description:"), found.Description)
	}

	if found.Remediation != "" {
		fmt.Fprintf(w, "\n%s\n%s\n", st.Bold("Remediation:"), st.Green(found.Remediation))
	}

	if len(found.Patterns) > 0 {
		fmt.Fprintf(w, "\n%s\n", st.Bold("Patterns:"))
		for i, p := range found.Patterns {
			fmt.Fprintf(w, "  %d. %s\n", i+1, st.Dim(p))
		}
	}

	if len(found.TruePositives) > 0 {
		fmt.Fprintf(w, "\n%s\n", st.Bold("True Positives:"))
		for _, ex := range found.TruePositives {
			fmt.Fprintf(w, "  %s %s\n", st.Red("✖"), ex)
		}
	}

	if len(found.FalsePositives) > 0 {
		fmt.Fprintf(w, "\n%s\n", st.Bold("False Positives:"))
		for _, ex := range found.FalsePositives {
			fmt.Fprintf(w, "  %s %s\n", st.Green("✔"), ex)
		}
	}

	fmt.Fprintln(w)
	return nil
}
