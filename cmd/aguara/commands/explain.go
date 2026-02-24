package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
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

	found, err := findRule(ruleID)
	if err != nil {
		return err
	}

	patterns := describePatterns(found)
	w := cmd.OutOrStdout()

	if strings.ToLower(flagFormat) == "json" {
		return writeExplainJSON(w, found, patterns)
	}
	return writeExplainTerminal(w, found, patterns)
}

func findRule(ruleID string) (*rules.CompiledRule, error) {
	rawRules, err := rules.LoadFromFS(builtin.FS())
	if err != nil {
		return nil, fmt.Errorf("loading built-in rules: %w", err)
	}
	if flagRules != "" {
		customRules, err := rules.LoadFromDir(flagRules)
		if err != nil {
			return nil, fmt.Errorf("loading custom rules from %s: %w", flagRules, err)
		}
		rawRules = append(rawRules, customRules...)
	}
	compiled, compileErrs := rules.CompileAll(rawRules)
	for _, e := range compileErrs {
		fmt.Fprintf(os.Stderr, "warning: %v\n", e)
	}

	for _, r := range compiled {
		if r.ID == ruleID {
			return r, nil
		}
	}
	return nil, fmt.Errorf("rule %q not found", ruleID)
}

func describePatterns(r *rules.CompiledRule) []string {
	patterns := make([]string, len(r.Patterns))
	for i, p := range r.Patterns {
		switch p.Type {
		case rules.PatternRegex:
			patterns[i] = fmt.Sprintf("[regex] %s", p.Regex.String())
		case rules.PatternContains:
			patterns[i] = fmt.Sprintf("[contains] %s", p.Value)
		}
	}
	return patterns
}

func writeExplainJSON(w io.Writer, r *rules.CompiledRule, patterns []string) error {
	info := explainInfo{
		ID:             r.ID,
		Name:           r.Name,
		Severity:       r.Severity.String(),
		Category:       r.Category,
		Description:    r.Description,
		Patterns:       patterns,
		TruePositives:  r.Examples.TruePositive,
		FalsePositives: r.Examples.FalsePositive,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(info)
}

func writeExplainTerminal(w io.Writer, found *rules.CompiledRule, patterns []string) error {
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
