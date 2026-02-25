package commands

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/garagon/aguara/internal/update"
)

// Version and Commit are set via ldflags at build time.
var (
	Version = "dev"
	Commit  = "none"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("aguara %s (commit: %s)\n", Version, Commit)
		if flagNoUpdateCheck {
			return
		}
		if r := update.CheckLatest(Version, "garagon/aguara"); r != nil && r.NeedsUpdate() {
			fmt.Fprintf(os.Stderr, "Update available: %s → %s\n", r.Latest, r.UpdateURL)
		}
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
