package commands

import (
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/garagon/aguara/internal/config"
)

var flagCategory string

var listRulesCmd = &cobra.Command{
	Use:     "list-rules",
	GroupID: groupRules,
	Short:   "List all available detection rules",
	RunE:    runListRules,
}

func init() {
	listRulesCmd.Flags().StringVar(&flagCategory, "category", "", "Filter by category")
	// A configuration error (unknown --disable-rule ID, invalid --rules
	// directory) is not command misuse; print the error without the usage
	// block, as scan, audit and explain do.
	listRulesCmd.SilenceUsage = true
	rootCmd.AddCommand(listRulesCmd)
}

func runListRules(cmd *cobra.Command, args []string) error {
	// The catalog merges YAML-compiled pattern rules, custom rules
	// from --rules, and every analyzer's RuleMetadata() into one
	// sorted slice. Before this consolidation `list-rules` only
	// surfaced YAML rules, so analyzer-emitted rules like
	// JS_DNS_TXT_EXFIL_001 or GHA_PWN_REQUEST_001 appeared in
	// findings but could not be listed or explained.
	// Same validation as scan: a custom rule that does not compile or
	// reuses an ID, or an unknown --disable-rule ID, is an error.
	res, err := resolveCLIRules(config.Config{}, flagDisableRules, cmd.ErrOrStderr())
	if err != nil {
		return err
	}
	cat := res.Catalog(flagCategory)

	w := cmd.OutOrStdout()

	if strings.ToLower(flagFormat) == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(cat)
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "ID\tNAME\tSEVERITY\tIMPACT\tCATEGORY\tANALYZER\n")
	fmt.Fprintf(tw, "--\t----\t--------\t------\t--------\t--------\n")
	for _, r := range cat {
		analyzer := r.Analyzer
		if analyzer == "" {
			analyzer = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			r.ID, r.Name, r.Severity, r.DecisionImpact, r.Category, analyzer)
	}
	_ = tw.Flush()
	fmt.Fprintf(w, "\n%d rules loaded\n", len(cat))

	return nil
}
