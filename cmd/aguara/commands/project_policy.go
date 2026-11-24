package commands

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/garagon/aguara/internal/config"
	"github.com/garagon/aguara/internal/output"
	"github.com/garagon/aguara/internal/scanner"
)

// projectConfigSettings lists the keys of a project .aguara.yml that cmd
// applies: set to a value other than the default and not overridden by a
// flag the caller passed. `aguara init` scaffolds a config whose
// severity and format are the defaults, so those alone are not listed.
// `ignore` is listed whenever it has patterns; callers that know whether
// the patterns excluded anything filter it.
func projectConfigSettings(cmd *cobra.Command, cfg config.Config) []string {
	changed := func(name string) bool { return cmd.Flags().Changed(name) }
	scan := cmd.Name() == "scan"
	var keys []string
	if len(cfg.Ignore) > 0 {
		keys = append(keys, "ignore")
	}
	if len(cfg.DisableRules) > 0 {
		keys = append(keys, "disable_rules")
	}
	if len(cfg.RuleOverrides) > 0 {
		keys = append(keys, "rule_overrides")
	}
	if cfg.Rules != "" && !changed("rules") {
		keys = append(keys, "rules")
	}
	if scan && cfg.FailOn != "" && !changed("fail-on") {
		keys = append(keys, "fail_on")
	}
	if scan && cfg.Severity != "" && !changed("severity") && !strings.EqualFold(strings.TrimSpace(cfg.Severity), "info") {
		keys = append(keys, "severity")
	}
	if cfg.Format != "" && !changed("format") {
		if canonical, ok := canonicalFormat(cmd, cfg.Format); ok && canonical != "terminal" {
			keys = append(keys, "format")
		}
	}
	if cfg.MaxFileSize > 0 && cfg.MaxFileSize != config.DefaultMaxFileSize && flagMaxFileSize == "" {
		keys = append(keys, "max_file_size")
	}
	writeBaseline := flagWriteBaseline
	if !scan {
		writeBaseline = flagAuditWriteBaseline
	}
	if cfg.Baseline != "" && !changed("baseline") && writeBaseline == "" {
		keys = append(keys, "baseline")
	}
	return keys
}

// noteProjectPolicy prints one stderr line when policy owned by the
// scanned project changed the result, naming what was applied. A
// repository can hide its own findings through these files, so a run
// that honored them says so. Files that changed nothing (for example
// the defaults `aguara init` scaffolds) are not named, and nothing is
// printed when no policy applied.
func noteProjectPolicy(cmd *cobra.Command, cfg config.Config, result *scanner.ScanResult) {
	var applied []string
	if cfg.Source != "" {
		keys := projectConfigSettings(cmd, cfg)
		if result.TargetPolicy.IgnorePatternExclusions == 0 {
			keys = slices.DeleteFunc(keys, func(k string) bool { return k == "ignore" })
		}
		if len(keys) > 0 {
			applied = append(applied, fmt.Sprintf("%s (%s)", cfg.Source, strings.Join(keys, ", ")))
		}
	}
	if result.TargetPolicy.IgnoreFile != "" {
		applied = append(applied, result.TargetPolicy.IgnoreFile)
	}
	if files := result.TargetPolicy.InlineSuppressed; len(files) > 0 {
		const maxListed = 3
		listed, more := files, ""
		if len(files) > maxListed {
			listed, more = files[:maxListed], fmt.Sprintf(" and %d more", len(files)-maxListed)
		}
		applied = append(applied, "inline aguara-ignore directives in "+strings.Join(listed, ", ")+more)
	}
	if len(applied) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "notice: applied policy owned by the scanned project: %s (pass --project-policy ignore to scan without it)\n",
		output.TerminalText(strings.Join(applied, "; ")))
}
