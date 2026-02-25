package commands

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/garagon/aguara/discover"
)

var discoverCmd = &cobra.Command{
	Use:   "discover",
	Short: "Discover MCP client configurations on this machine",
	Long:  `Scans well-known paths for 17 MCP client applications and lists their configured servers.`,
	Args:  cobra.NoArgs,
	RunE:  runDiscover,
}

func init() {
	rootCmd.AddCommand(discoverCmd)
}

func runDiscover(cmd *cobra.Command, args []string) error {
	result, err := discover.Scan()
	if err != nil {
		return fmt.Errorf("discovery failed: %w", err)
	}

	switch flagFormat {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	default:
		fmt.Print(discover.FormatTree(result))
		return nil
	}
}
