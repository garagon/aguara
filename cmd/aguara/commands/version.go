package commands

import (
	"fmt"

	"github.com/spf13/cobra"
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
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
