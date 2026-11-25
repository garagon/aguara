package commands

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/garagon/aguara/internal/output"
	"github.com/garagon/aguara/internal/update"
)

// Version and Commit are set via ldflags at build time.
var (
	Version = "dev"
	Commit  = "none"
)

var versionCmd = &cobra.Command{
	Use:     "version",
	GroupID: groupSetup,
	Short:   "Print the version",
	Long: `Print the version and commit of this binary.

With --format json, print the same identity the JSON reports of scan,
check and audit start with: schema_version, tool (name, version, commit)
and catalog (detection, pattern rule and analyzer rule counts, and the
digest of the built-in rule catalog). A newer-release notice, when there
is one, goes to stderr in both formats.`,
	Example: `  aguara version
  aguara version --format json`,
	Run: func(cmd *cobra.Command, args []string) {
		if flagFormat == "json" {
			if err := output.EncodeJSONReport(cmd.OutOrStdout(), reportHeader(builtinCatalog()), struct{}{}); err != nil {
				fmt.Fprintf(os.Stderr, "warning: %v\n", err)
			}
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "aguara %s (commit: %s)\n", Version, Commit)
		}
		if flagNoUpdateCheck {
			return
		}
		if r := update.CheckLatest(Version, "garagon/aguara"); r != nil && r.NeedsUpdate() {
			fmt.Fprintf(os.Stderr, "Update available: %s → %s\n", r.Latest, r.UpdateURL)
		}
	},
}

func init() {
	addFormatFlag(versionCmd, "terminal", "json")
	rootCmd.AddCommand(versionCmd)
}
