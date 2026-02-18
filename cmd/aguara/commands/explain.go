package commands

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/garagon/aguara/internal/rules"
	"github.com/garagon/aguara/internal/rules/builtin"
)

var explainCmd = &cobra.Command{
	Use:   "explain <RULE_ID>",
	Short: "Show detailed information about a detection rule",
	Args:  cobra.ExactArgs(1),
	RunE:  runExplain,
}

func init() {
	rootCmd.AddCommand(explainCmd)
}

type explainInfo struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Severity       string   `json:"severity"`
	Category       string   `json:"category"`
	Description    string   `json:"description"`
	Patterns       []string `json:"patterns"`
	TruePositives  []string `json:"true_positives"`
	FalsePositives []string `json:"false_positives"`
}

func runExplain(cmd *cobra.Command, args []string) error {
	ruleID := strings.ToUpper(strings.TrimSpace(args[0]))

	// Load and compile rules
	rawRules, err := rules.LoadFromFS(builtin.FS())
	if err != nil {
		return fmt.Errorf("loading built-in rules: %w", err)
	}
	if flagRules != "" {
		customRules, err := rules.LoadFromDir(flagRules)
		if err != nil {
			return fmt.Errorf("loading custom rules from %s: %w", flagRules, err)
		}
		rawRules = append(rawRules, customRules...)
	}
	compiled, _ := rules.CompileAll(rawRules)

	// Find the rule
	var found *rules.CompiledRule
	for _, r := range compiled {
		if r.ID == ruleID {
			found = r
			break
		}
	}
	if found == nil {
		return fmt.Errorf("rule %q not found", ruleID)
	}

	// Build pattern descriptions
	patterns := make([]string, len(found.Patterns))
	for i, p := range found.Patterns {
		switch p.Type {
		case rules.PatternRegex:
			patterns[i] = fmt.Sprintf("[regex] %s", p.Regex.String())
		case rules.PatternContains:
			patterns[i] = fmt.Sprintf("[contains] %s", p.Value)
		}
	}

	w := cmd.OutOrStdout()

	if strings.ToLower(flagFormat) == "json" {
		info := explainInfo{
			ID:             found.ID,
			Name:           found.Name,
			Severity:       found.Severity.String(),
			Category:       found.Category,
			Description:    found.Description,
			Patterns:       patterns,
			TruePositives:  found.Examples.TruePositive,
			FalsePositives: found.Examples.FalsePositive,
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(info)
	}

	// Terminal output
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
	switch found.Severity.String() {
	case "CRITICAL":
		sevColor = red + bold
	case "HIGH":
		sevColor = red
	case "MEDIUM":
		sevColor = yellow
	}

	fmt.Fprintf(w, "\n%s %s\n", color(dim, "Rule:"), color(bold, found.ID))
	fmt.Fprintf(w, "%s %s\n", color(dim, "Name:"), found.Name)
	fmt.Fprintf(w, "%s %s\n", color(dim, "Severity:"), color(sevColor, found.Severity.String()))
	fmt.Fprintf(w, "%s %s\n", color(dim, "Category:"), found.Category)

	if found.Description != "" {
		fmt.Fprintf(w, "\n%s\n%s\n", color(bold, "Description:"), found.Description)
	}

	if len(patterns) > 0 {
		fmt.Fprintf(w, "\n%s\n", color(bold, "Patterns:"))
		for i, p := range patterns {
			fmt.Fprintf(w, "  %d. %s\n", i+1, color(dim, p))
		}
	}

	if len(found.Examples.TruePositive) > 0 {
		fmt.Fprintf(w, "\n%s\n", color(bold, "True Positives:"))
		for _, ex := range found.Examples.TruePositive {
			fmt.Fprintf(w, "  %s %s\n", color(red, "\u2716"), ex)
		}
	}

	if len(found.Examples.FalsePositive) > 0 {
		fmt.Fprintf(w, "\n%s\n", color(bold, "False Positives:"))
		for _, ex := range found.Examples.FalsePositive {
			fmt.Fprintf(w, "  %s %s\n", color(green, "\u2714"), ex)
		}
	}

	fmt.Fprintln(w)
	return nil
}
