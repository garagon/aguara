package commands

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/garagon/aguara/discover"
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

func runDiscover(cmd *cobra.Command, args []string) error {
	result, err := discover.Scan()
	if err != nil {
		return fmt.Errorf("discovery failed: %w", err)
	}

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
