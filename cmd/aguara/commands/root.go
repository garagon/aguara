// Package commands implements the Cobra CLI for aguara: scan, init,
// list-rules, explain, and version subcommands.
package commands

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/garagon/aguara/internal/output"
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

// Help groups: every command declares one of these as its GroupID so
// `aguara --help` reads as workflows instead of an alphabetical list.
const (
	groupScan  = "scan"
	groupRules = "rules"
	groupSetup = "setup"
)

var rootCmd = &cobra.Command{
	Use:   "aguara",
	Short: "Security engine for AI agent and supply-chain trust",
	Long: `Aguara is an open source security engine for AI agent and supply-chain
trust. It detects prompt injection, data exfiltration, credential leaks,
and known-compromised packages across AI agent skills, MCP servers, CI
workflows, and dependency lockfiles. No SaaS account, no telemetry, no
LLM calls; default runs stay offline.`,
	Example: `  aguara scan ./my-skill     Scan a skill or MCP server directory
  aguara audit . --ci        Package check + content scan, one verdict, gate CI
  aguara check               Check dependencies for known-compromised packages
  aguara explain CRED_001    Show what a rule detects and how to fix it`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if err := validateFormatFlag(cmd); err != nil {
			return err
		}
		resolveColorMode()
		return nil
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		checkPathHint()
	},
}

// resolveColorMode disables color before any command runs when the
// destination cannot render it: NO_COLOR set (https://no-color.org),
// --output redirecting to a file, or stdout not attached to an
// interactive terminal (pipes, CI logs, shell redirection). --no-color
// stays the explicit override; per-command --ci handling may still
// disable color afterwards.
func resolveColorMode() {
	if flagNoColor {
		return
	}
	if os.Getenv("NO_COLOR") != "" || flagOutput != "" || !output.IsTerminal(os.Stdout) {
		flagNoColor = true
	}
}

func init() {
	rootCmd.Version = Version
	rootCmd.AddGroup(
		&cobra.Group{ID: groupScan, Title: "Scan & audit:"},
		&cobra.Group{ID: groupRules, Title: "Rules & threat intel:"},
		&cobra.Group{ID: groupSetup, Title: "Setup:"},
	)
	rootCmd.SetHelpCommandGroupID(groupSetup)
	rootCmd.SetCompletionCommandGroupID(groupSetup)
	// Only opt-outs that every command satisfies stay global: a command
	// that prints no color or never checks for updates already honors
	// them, and wrappers pass them unconditionally (the GitHub Action,
	// the release smoke tests). Output and analysis flags are registered
	// per command in flags.go so an ignored flag is rejected instead.
	rootCmd.PersistentFlags().BoolVar(&flagNoColor, "no-color", false, "Disable colored output")
	rootCmd.PersistentFlags().BoolVar(&flagNoUpdateCheck, "no-update-check", false, "Disable the release update check")
	rootCmd.SetFlagErrorFunc(scopedFlagError)
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
// scan also uses it to resolve --project-policy auto to ignore, so a
// repository under review in CI cannot suppress its own findings.
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
