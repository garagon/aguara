package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/garagon/aguara/discover"
	"github.com/garagon/aguara/internal/output"
)

var discoverCmd = &cobra.Command{
	Use:     "discover",
	GroupID: groupScan,
	Short:   "Discover MCP client configurations on this machine",
	Long:    `Scans well-known paths for 17 MCP client applications and lists their configured servers.`,
	Args:    cobra.NoArgs,
	RunE:    runDiscover,
}

func init() {
	addFormatFlag(discoverCmd, "terminal", "json", "markdown")
	addOutputFlag(discoverCmd)
	rootCmd.AddCommand(discoverCmd)
}

// printDiscoverWarnings reports configuration entries discovery read
// leniently or skipped, on stderr, for discover and scan --auto.
func printDiscoverWarnings(result *discover.Result) {
	for _, c := range result.Clients {
		for _, w := range c.Warnings {
			fmt.Fprintf(os.Stderr, "warning: %s\n", output.TerminalText(w))
		}
	}
}

func runDiscover(cmd *cobra.Command, args []string) error {
	result, err := discover.Scan()
	if err != nil {
		return fmt.Errorf("discovery failed: %w", err)
	}
	printDiscoverWarnings(result)

	return writeReport(func(w io.Writer) error {
		switch flagFormat {
		case "json":
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			return enc.Encode(result.Redacted())
		case "markdown", "md":
			_, err := fmt.Fprint(w, discover.FormatMarkdown(result))
			return err
		default:
			_, err := fmt.Fprint(w, discover.FormatTree(result))
			return err
		}
	})
}
