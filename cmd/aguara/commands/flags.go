package commands

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// Output and analysis flags are registered only on the commands that
// honor them. A flag registered globally would be accepted by every
// command, including the ones that silently ignore it (for example
// `aguara status --format json` printing text, or `aguara check --rules
// dir` loading no rules). Registering per command turns those calls
// into a parse error that names the commands where the flag applies.
//
// Every helper binds the same package-level variable, so the command
// code reads flagFormat / flagOutput / ... exactly as before.

// formatsAnnotation stores the output formats a command supports on
// its --format flag, so validation and shell completion read one list.
const formatsAnnotation = "aguara_formats"

// formatAliases maps accepted spellings to their canonical format name.
var formatAliases = map[string]string{"md": "markdown"}

// addFormatFlag registers --format with the formats the command
// actually renders. The first entry is the default.
func addFormatFlag(cmd *cobra.Command, formats ...string) {
	names := make([]string, 0, len(formats))
	for _, f := range formats {
		name := f
		for alias, canonical := range formatAliases {
			if canonical == f {
				name += " (alias: " + alias + ")"
			}
		}
		names = append(names, name)
	}
	cmd.Flags().StringVar(&flagFormat, "format", formats[0], "Output format: "+strings.Join(names, ", "))
	_ = cmd.Flags().SetAnnotation("format", formatsAnnotation, formats)
	_ = cmd.RegisterFlagCompletionFunc("format", cobra.FixedCompletions(formats, cobra.ShellCompDirectiveNoFileComp))
}

// addOutputFlag registers -o/--output for commands that write a report.
func addOutputFlag(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&flagOutput, "output", "o", "", "Output file path (default: stdout)")
}

// addSeverityFlag registers --severity, the minimum severity a content
// scan reports.
func addSeverityFlag(cmd *cobra.Command) {
	cmd.Flags().StringVar(&flagSeverity, "severity", "info", "Minimum severity to report (critical, high, medium, low, info)")
}

// addWorkersFlag registers --workers for commands that run the content
// scanner.
func addWorkersFlag(cmd *cobra.Command) {
	cmd.Flags().IntVar(&flagWorkers, "workers", 0, "Number of worker goroutines (default: NumCPU)")
}

// addRulesFlag registers --rules for commands that load the rule catalog.
func addRulesFlag(cmd *cobra.Command) {
	cmd.Flags().StringVar(&flagRules, "rules", "", "Additional rules directory")
}

// addDisableRuleFlag registers --disable-rule for commands that filter
// the rule catalog.
func addDisableRuleFlag(cmd *cobra.Command) {
	cmd.Flags().StringSliceVar(&flagDisableRules, "disable-rule", nil, "Rule IDs to disable (comma-separated, repeatable)")
}

// flagScopeHints adds command-specific guidance to the rejection of a
// flag that another command accepts. Keyed by "<command> --<flag>".
var flagScopeHints = map[string]string{
	"audit --severity": "audit always reports every severity; use --fail-on to choose what fails the run",
}

// scopedFlagError rewrites "unknown flag" parse errors for flags that a
// different command accepts, so `aguara check --rules dir` explains that
// --rules does nothing for check instead of reading like a typo. Other
// parse errors pass through unchanged. Either way the command fails
// before running, which main maps to exit code 2.
func scopedFlagError(cmd *cobra.Command, err error) error {
	name, short := unknownFlagFromError(err)
	if name == "" && short == "" {
		return err
	}
	var owners []string
	for _, c := range cmd.Root().Commands() {
		if c == cmd {
			continue
		}
		f := c.LocalNonPersistentFlags().Lookup(name)
		if f == nil && short != "" {
			f = c.LocalNonPersistentFlags().ShorthandLookup(short)
		}
		if f == nil {
			continue
		}
		name = f.Name
		owners = append(owners, c.CommandPath())
	}
	if len(owners) == 0 {
		return err
	}
	msg := fmt.Sprintf("%s does not accept --%s (it has no effect there); it is accepted by: %s",
		cmd.CommandPath(), name, strings.Join(owners, ", "))
	if hint := flagScopeHints[cmd.Name()+" --"+name]; hint != "" {
		msg += "; " + hint
	}
	return errors.New(msg)
}

// unknownFlagFromError extracts the flag name (or shorthand letter) from
// pflag's unknown-flag errors:
//
//	unknown flag: --severity
//	unknown shorthand flag: 'o' in -o
func unknownFlagFromError(err error) (name, short string) {
	msg := err.Error()
	if rest, ok := strings.CutPrefix(msg, "unknown flag: --"); ok {
		return rest, ""
	}
	if rest, ok := strings.CutPrefix(msg, "unknown shorthand flag: '"); ok {
		if r, _, ok := strings.Cut(rest, "'"); ok && r != "" {
			return "", r
		}
	}
	return "", ""
}
