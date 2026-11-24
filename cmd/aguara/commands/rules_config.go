package commands

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/garagon/aguara/internal/config"
	"github.com/garagon/aguara/internal/rulecatalog"
	"github.com/garagon/aguara/internal/rules"
	"github.com/garagon/aguara/internal/types"
)

// Sources used in configuration problems for CLI inputs.
const sourceDisableFlag = "--disable-rule"

// resolveCLIRules loads the built-in rules plus every --rules directory and
// validates the rule IDs in disable (the --disable-rule values) and, when cfg
// came from a project file, in its disable_rules and rule_overrides.
//
// The CLI applies the same validation as the library, with one difference
// in how problems are handled:
//
//   - Problems in caller input are fatal and returned as a
//     *types.ConfigError: custom rules that do not compile or reuse an
//     existing ID (whichever way the directory was named), and unknown IDs
//     in --disable-rule.
//   - Problems in .aguara.yml (unknown rule IDs, invalid severities) are
//     printed as warnings to warn and the scan continues. Existing project
//     files may name rules from a different Aguara version or from a
//     consumer's own rule pack, and this file has always been warn-only;
//     the warnings say exactly which entry was ignored.
func resolveCLIRules(cfg config.Config, disable []string, warn io.Writer) (*rulecatalog.Resolution, error) {
	dirs, err := resolveRulesDirs(flagRules)
	if err != nil {
		return nil, err
	}
	in := rulecatalog.Input{CustomRulesDirs: dirs}

	cfgFile := cfg.File
	if cfgFile == "" {
		cfgFile = ".aguara.yml"
	}
	fileDisable := cfgFile + " disable_rules"
	fileOverrides := cfgFile + " rule_overrides"
	for _, id := range cfg.DisableRules {
		in.Disabled = append(in.Disabled, rulecatalog.Ref{ID: id, Source: fileDisable})
	}
	for _, id := range disable {
		in.Disabled = append(in.Disabled, rulecatalog.Ref{ID: id, Source: sourceDisableFlag})
	}
	ids := make([]string, 0, len(cfg.RuleOverrides))
	for id := range cfg.RuleOverrides {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		ovr := cfg.RuleOverrides[id]
		in.Overrides = append(in.Overrides, rulecatalog.OverrideRef{
			ID:     id,
			Source: fileOverrides,
			Override: rules.RuleOverride{
				Severity:     ovr.Severity,
				Disabled:     ovr.Disabled,
				ApplyToTools: ovr.ApplyToTools,
				ExemptTools:  ovr.ExemptTools,
			},
		})
	}

	res, err := rulecatalog.Resolve(in)
	if err != nil {
		return nil, err
	}
	var fatal []types.ConfigProblem
	for _, p := range res.Problems {
		if p.Source == fileDisable || p.Source == fileOverrides {
			fmt.Fprintf(warn, "warning: %s (ignored)\n", p)
			continue
		}
		fatal = append(fatal, p)
	}
	if len(fatal) > 0 {
		return nil, &types.ConfigError{Problems: fatal}
	}
	return res, nil
}

// resolveRulesDirs turns the --rules values into absolute directory paths,
// in order, without repeats. Each value must name an existing directory.
func resolveRulesDirs(values []string) ([]string, error) {
	var dirs []string
	for _, value := range values {
		if value == "" {
			continue
		}
		rulesDir, err := filepath.Abs(value)
		if err != nil {
			return nil, fmt.Errorf("resolving rules path: %w", err)
		}
		info, err := os.Stat(rulesDir)
		if err != nil {
			return nil, fmt.Errorf("rules directory: %w", err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("--rules path is not a directory: %s", rulesDir)
		}
		dirs = append(dirs, rulesDir)
	}
	return rules.UniqueDirs(dirs), nil
}
