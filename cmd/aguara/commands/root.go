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
	rootCmd.Version = Version
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
	if os.Getenv("AGUARA_NO_UPDATE_CHECK") == "1" || isCI() {
		flagNoUpdateCheck = true
	}
	return rootCmd.Execute()
}

// isCI reports whether aguara is running inside a recognized CI environment.
// In CI the update check is a net-egress side effect with no user to notify,
// so it is silently suppressed. Local invocations still get the notice unless
// the user opts out with --no-update-check or AGUARA_NO_UPDATE_CHECK=1.
//
// The ci env var is the de-facto standard and covers GitHub Actions, GitLab,
// CircleCI, Travis, Buildkite, Bitbucket Pipelines, Drone, Woodpecker, and
// most others. The explicit names are a fallback for runners that leave CI
// unset (Jenkins historically, TeamCity).
func isCI() bool {
	if v := os.Getenv("CI"); v != "" && v != "false" && v != "0" {
		return true
	}
	for _, k := range [...]string{
		"GITHUB_ACTIONS",
		"GITLAB_CI",
		"CIRCLECI",
		"BUILDKITE",
		"JENKINS_URL",
		"TEAMCITY_VERSION",
		"TRAVIS",
	} {
		if os.Getenv(k) != "" {
			return true
		}
	}
	return false
}
