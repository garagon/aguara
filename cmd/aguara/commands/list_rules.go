package commands

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/garagon/aguara/internal/rules"
	"github.com/garagon/aguara/internal/rules/builtin"
)

var flagCategory string

var listRulesCmd = &cobra.Command{
	Use:   "list-rules",
	Short: "List all available detection rules",
	RunE:  runListRules,
}

func init() {
	listRulesCmd.Flags().StringVar(&flagCategory, "category", "", "Filter by category")
	rootCmd.AddCommand(listRulesCmd)
}

type ruleInfo struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Category string `json:"category"`
}

func runListRules(cmd *cobra.Command, args []string) error {
	// Load built-in rules
	rawRules, err := rules.LoadFromFS(builtin.FS())
	if err != nil {
		return fmt.Errorf("loading built-in rules: %w", err)
	}

	// Load custom rules if specified
	if flagRules != "" {
		customRules, err := rules.LoadFromDir(flagRules)
		if err != nil {
			return fmt.Errorf("loading custom rules from %s: %w", flagRules, err)
		}
		rawRules = append(rawRules, customRules...)
	}

	// Compile rules
	compiled, _ := rules.CompileAll(rawRules)

	// Apply config rule overrides (best-effort config load)
	if len(args) > 0 {
		// config from path not applicable for list-rules
	}

	// Apply --disable-rule flag
	if len(flagDisableRules) > 0 {
		disabled := make(map[string]bool)
		for _, id := range flagDisableRules {
			disabled[strings.TrimSpace(id)] = true
		}
		compiled = rules.FilterByIDs(compiled, disabled)
	}

	// Sort by rule ID
	sort.Slice(compiled, func(i, j int) bool {
		return compiled[i].ID < compiled[j].ID
	})

	// Filter by category
	if flagCategory != "" {
		var filtered []*rules.CompiledRule
		for _, r := range compiled {
			if r.Category == flagCategory {
				filtered = append(filtered, r)
			}
		}
		compiled = filtered
	}

	w := cmd.OutOrStdout()

	if strings.ToLower(flagFormat) == "json" {
		infos := make([]ruleInfo, len(compiled))
		for i, r := range compiled {
			infos[i] = ruleInfo{
				ID:       r.ID,
				Name:     r.Name,
				Severity: r.Severity.String(),
				Category: r.Category,
			}
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(infos)
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "ID\tNAME\tSEVERITY\tCATEGORY\n")
	fmt.Fprintf(tw, "--\t----\t--------\t--------\n")
	for _, r := range compiled {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.ID, r.Name, r.Severity.String(), r.Category)
	}
	tw.Flush()
	fmt.Fprintf(w, "\n%d rules loaded\n", len(compiled))

	return nil
}
