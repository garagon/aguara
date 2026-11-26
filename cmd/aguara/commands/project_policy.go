package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/garagon/aguara/internal/config"
	"github.com/garagon/aguara/internal/output"
	"github.com/garagon/aguara/internal/rulecatalog"
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

// isAutoProjectPolicy reports whether --project-policy was left to auto.
func isAutoProjectPolicy(value string) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	return v == "" || v == "auto"
}

// applyCIProjectPolicy handles `scan` with --project-policy auto in a
// detected CI environment without --ci. Policy owned by the scanned
// project is not applied, with one exception: a fail_on in .aguara.yml
// still applies when --fail-on was not passed. A failure threshold can
// only add a gate: without --fail-on and --ci this run has none to
// loosen, while the settings that can hide findings (ignore,
// disable_rules, rule_overrides, severity, baseline) stay unapplied.
// One stderr notice says what was and was not applied, naming the CI
// variable so a developer with it exported locally can see why.
func applyCIProjectPolicy(cmd *cobra.Command, targetPath, ciVar string) error {
	cfg, err := config.Load(targetPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	}
	info, statErr := os.Stat(targetPath)
	walked := statErr == nil && info.IsDir() && !flagChanged // ignore lists apply only to a directory walk

	var skipped []string
	appliedFailOn := ""
	if cfg.Source != "" {
		keys := projectConfigSettings(cmd, cfg)
		if !walked {
			keys = slices.DeleteFunc(keys, func(k string) bool { return k == "ignore" })
		}
		if slices.Contains(keys, "fail_on") {
			if _, err := parseFailOn(cfg.FailOn); err != nil {
				return fmt.Errorf("%s: invalid fail_on %q: choose %s", cfg.Source, cfg.FailOn, failOnChoices)
			}
			flagFailOn = cfg.FailOn
			flagFailOnSource = cfg.Source + " fail_on"
			appliedFailOn = cfg.FailOn
			keys = slices.DeleteFunc(keys, func(k string) bool { return k == "fail_on" })
		}
		if len(keys) > 0 {
			skipped = append(skipped, fmt.Sprintf("%s (%s)", cfg.Source, strings.Join(keys, ", ")))
		}
	}
	if walked {
		if path, ok := projectIgnoreFile(targetPath); ok {
			skipped = append(skipped, path)
		}
	}

	var parts []string
	if len(skipped) > 0 {
		parts = append(parts, "not applying policy owned by the scanned project: "+strings.Join(skipped, ", ")+
			" (pass --project-policy trust if the pipeline owns these files)")
	}
	if appliedFailOn != "" {
		parts = append(parts, fmt.Sprintf("applying fail_on: %s from %s, because a failure threshold can only add a gate", appliedFailOn, cfg.Source))
	}
	if len(parts) == 0 {
		return nil
	}
	fmt.Fprintf(os.Stderr, "notice: CI environment detected (%s); %s\n", ciVar, output.TerminalText(strings.Join(parts, "; ")))
	return nil
}

// projectIgnoreFile reports the target's .aguaraignore when it holds at
// least one pattern, or exists but is not a regular file (a trusted scan
// would fail on it).
func projectIgnoreFile(dir string) (string, bool) {
	path := filepath.Join(dir, ".aguaraignore")
	info, err := os.Lstat(path)
	if err != nil {
		return "", false
	}
	if !info.Mode().IsRegular() {
		return path, true
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return path, true
	}
	for _, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			return path, true
		}
	}
	return "", false
}

// noteProjectPolicy prints one stderr line when policy owned by the
// scanned project changed the result, naming what was applied. A
// repository can hide its own findings through these files, so a run
// that honored them says so. Files that changed nothing (for example
// the defaults `aguara init` scaffolds) are not named, and nothing is
// printed when no policy applied.
func noteProjectPolicy(cmd *cobra.Command, cfg config.Config, res *rulecatalog.Resolution, result *scanner.ScanResult) {
	var applied []string
	if cfg.Source != "" {
		keys := projectConfigSettings(cmd, cfg)
		if result.TargetPolicy.IgnorePatternExclusions == 0 {
			keys = slices.DeleteFunc(keys, func(k string) bool { return k == "ignore" })
		}
		keys = slices.DeleteFunc(keys, func(k string) bool {
			return (k == "disable_rules" && !fileDisablesApply(cfg, res)) ||
				(k == "rule_overrides" && !fileOverridesApply(cfg, res))
		})
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

// flagDisabled reports whether --disable-rule names the canonical id.
func flagDisabled(id string) bool {
	return slices.ContainsFunc(flagDisableRules, func(v string) bool { return rulecatalog.CanonicalID(v) == id })
}

// fileDisablesApply reports whether a disable_rules entry of cfg took
// effect. resolveCLIRules warns about and drops an entry naming an
// unknown rule, so only known IDs reach res.Disabled; an entry that
// --disable-rule already covers changes nothing.
func fileDisablesApply(cfg config.Config, res *rulecatalog.Resolution) bool {
	for _, entry := range cfg.DisableRules {
		id := rulecatalog.CanonicalID(entry)
		if id != "" && slices.Contains(res.Disabled, id) && !flagDisabled(id) {
			return true
		}
	}
	return false
}

// fileOverridesApply reports whether a rule_overrides entry of cfg took
// effect. An entry naming an unknown rule is dropped, an invalid
// severity is cleared, and an override of a rule that --disable-rule
// removes changes nothing.
func fileOverridesApply(cfg config.Config, res *rulecatalog.Resolution) bool {
	for entry := range cfg.RuleOverrides {
		id := rulecatalog.CanonicalID(entry)
		ovr, ok := res.Overrides[id]
		if !ok || flagDisabled(id) {
			continue
		}
		if ovr.Severity != "" || ovr.Disabled || len(ovr.ApplyToTools) > 0 || len(ovr.ExemptTools) > 0 {
			return true
		}
	}
	return false
}
