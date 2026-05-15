package commands

import (
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/garagon/aguara/internal/rulecatalog"
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

func runListRules(cmd *cobra.Command, args []string) error {
	// The catalog merges YAML-compiled pattern rules, custom rules
	// from --rules, and every analyzer's RuleMetadata() into one
	// sorted slice. Before this consolidation `list-rules` only
	// surfaced YAML rules, so analyzer-emitted rules like
	// JS_DNS_TXT_EXFIL_001 or GHA_PWN_REQUEST_001 appeared in
	// findings but could not be listed or explained.
	cat, err := rulecatalog.Build(rulecatalog.Options{
		CustomRulesDir: flagRules,
		DisableRuleIDs: flagDisableRules,
		Category:       flagCategory,
		Warn: func(format string, a ...any) {
			fmt.Fprintf(cmd.ErrOrStderr(), format, a...)
		},
	})
	if err != nil {
		return err
	}

	w := cmd.OutOrStdout()

	if strings.ToLower(flagFormat) == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(cat)
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "ID\tNAME\tSEVERITY\tCATEGORY\tANALYZER\n")
	fmt.Fprintf(tw, "--\t----\t--------\t--------\t--------\n")
	for _, r := range cat {
		analyzer := r.Analyzer
		if analyzer == "" {
			analyzer = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.ID, r.Name, r.Severity, r.Category, analyzer)
	}
	_ = tw.Flush()
	fmt.Fprintf(w, "\n%d rules loaded\n", len(cat))

	return nil
}
