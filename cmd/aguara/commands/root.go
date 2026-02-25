// Package commands implements the Cobra CLI for aguara: scan, init,
// list-rules, explain, and version subcommands.
package commands

import (
	"os"

	"github.com/spf13/cobra"
)

var (
	flagSeverity      string
	flagFormat        string
	flagOutput        string
	flagWorkers       int
	flagRules         string
	flagNoColor       bool
	flagDisableRules  []string
	flagNoUpdateCheck bool
)

var rootCmd = &cobra.Command{
	Use:   "aguara",
	Short: "Security scanner for AI agent skills and MCP servers",
	Long:  `Aguara is a security scanner that detects prompt injection, data exfiltration, and credential leaks in AI agent skill definitions and MCP server configurations.`,
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		checkPathHint()
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&flagSeverity, "severity", "info", "Minimum severity to report (critical, high, medium, low, info)")
	rootCmd.PersistentFlags().StringVar(&flagFormat, "format", "terminal", "Output format (terminal, json, sarif, markdown)")
	rootCmd.PersistentFlags().StringVarP(&flagOutput, "output", "o", "", "Output file path (default: stdout)")
	rootCmd.PersistentFlags().IntVar(&flagWorkers, "workers", 0, "Number of worker goroutines (default: NumCPU)")
	rootCmd.PersistentFlags().StringVar(&flagRules, "rules", "", "Additional rules directory")
	rootCmd.PersistentFlags().BoolVar(&flagNoColor, "no-color", false, "Disable colored output")
	rootCmd.PersistentFlags().StringSliceVar(&flagDisableRules, "disable-rule", nil, "Rule IDs to disable (comma-separated, repeatable)")
	rootCmd.PersistentFlags().BoolVar(&flagNoUpdateCheck, "no-update-check", false, "Disable update check")
}

// Execute runs the root command.
func Execute() error {
	if os.Getenv("AGUARA_NO_UPDATE_CHECK") == "1" {
		flagNoUpdateCheck = true
	}
	return rootCmd.Execute()
}
