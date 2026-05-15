// Package rulecatalog combines YAML-compiled pattern rules, custom
// --rules-dir rules, and analyzer-emitted rule metadata into one
// queryable []rulemeta.Rule. The CLI (explain, list-rules) and the
// public Go API (aguara.ListRules / aguara.ExplainRule) both consume
// the catalog, so a user can `aguara explain JS_DNS_TXT_EXFIL_001`
// even though that rule originates from internal/engine/jsrisk
// rather than from a YAML file.
//
// Catalog construction is pure: no file I/O beyond what the caller
// asks for via Options. The pattern-rule load path is the same one
// the scanner uses, so the catalog and the runtime see identical
// rule sets.
package rulecatalog

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/garagon/aguara/internal/engine/ci"
	"github.com/garagon/aguara/internal/engine/jsrisk"
	"github.com/garagon/aguara/internal/engine/nlp"
	"github.com/garagon/aguara/internal/engine/pkgmeta"
	"github.com/garagon/aguara/internal/engine/toxicflow"
	"github.com/garagon/aguara/internal/rulemeta"
	"github.com/garagon/aguara/internal/rules"
	"github.com/garagon/aguara/internal/rules/builtin"
)

// Options controls Build. All fields are optional; the zero value
// builds the full catalog (every YAML rule + every analyzer rule).
type Options struct {
	// CustomRulesDir, when non-empty, loads additional YAML rules
	// from a directory and merges them in. Matches the --rules
	// flag the CLI exposes.
	CustomRulesDir string
	// DisableRuleIDs filters by exact ID match before returning.
	// Matches the --disable-rule CLI flag and the config-file
	// disable_rules list.
	DisableRuleIDs []string
	// Category, when non-empty, filters the result to rules whose
	// Category matches case-insensitively.
	Category string
	// Warn receives non-fatal compile warnings from the YAML rule
	// loader. nil discards them; the CLI wires this to stderr so
	// the user sees rule-author issues during `list-rules`.
	Warn func(format string, args ...any)
}

// Build returns the merged catalog. Errors come from the
// custom-rules directory path (missing dir, malformed YAML); built-
// in rules are embedded and always succeed.
//
// Returned slice is sorted by ID so the CLI output is stable
// across runs.
func Build(opts Options) ([]rulemeta.Rule, error) {
	warn := opts.Warn
	if warn == nil {
		warn = func(string, ...any) {}
	}

	// 1. Built-in pattern rules (embedded YAML files).
	rawRules, err := rules.LoadFromFS(builtin.FS())
	if err != nil {
		return nil, fmt.Errorf("rulecatalog: load built-in rules: %w", err)
	}

	// 2. Custom rules dir, when configured.
	if opts.CustomRulesDir != "" {
		customRules, err := rules.LoadFromDir(opts.CustomRulesDir)
		if err != nil {
			return nil, fmt.Errorf("rulecatalog: load custom rules from %s: %w", opts.CustomRulesDir, err)
		}
		rawRules = append(rawRules, customRules...)
	}

	// Compile the YAML rules; compile warnings (regex too long,
	// missing example, etc.) flow to the caller's warn func so
	// the CLI surfaces them on stderr.
	compiled, compileErrs := rules.CompileAll(rawRules)
	for _, e := range compileErrs {
		warn("warning: %v\n", e)
	}

	// 3. Convert compiled YAML rules into the catalog shape.
	out := make([]rulemeta.Rule, 0, len(compiled)+32)
	for _, r := range compiled {
		out = append(out, fromCompiledRule(r))
	}

	// 4. Analyzer-emitted rules. Order doesn't matter; the sort
	// at the end establishes the canonical ordering.
	out = append(out, ci.RuleMetadata()...)
	out = append(out, pkgmeta.RuleMetadata()...)
	out = append(out, jsrisk.RuleMetadata()...)
	out = append(out, nlp.RuleMetadata()...)
	out = append(out, toxicflow.RuleMetadata()...)

	// 5. --disable-rule filter. Applied AFTER merge so users can
	// disable analyzer rules too (same UX as YAML rules).
	if len(opts.DisableRuleIDs) > 0 {
		disabled := make(map[string]struct{}, len(opts.DisableRuleIDs))
		for _, id := range opts.DisableRuleIDs {
			disabled[strings.ToUpper(strings.TrimSpace(id))] = struct{}{}
		}
		filtered := out[:0]
		for _, r := range out {
			if _, drop := disabled[strings.ToUpper(r.ID)]; drop {
				continue
			}
			filtered = append(filtered, r)
		}
		out = filtered
	}

	// 6. --category filter. Case-insensitive on the Category
	// string; same UX as the legacy YAML-only list-rules.
	if opts.Category != "" {
		filtered := out[:0]
		for _, r := range out {
			if strings.EqualFold(r.Category, opts.Category) {
				filtered = append(filtered, r)
			}
		}
		out = filtered
	}

	// 7. Canonical order.
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// FindByID returns the catalog entry with the given ID (case-
// insensitive) or os.ErrNotExist when nothing matches. Used by
// explain.go and aguara.ExplainRule so both surfaces share one
// lookup path.
func FindByID(opts Options, id string) (*rulemeta.Rule, error) {
	id = strings.ToUpper(strings.TrimSpace(id))
	cat, err := Build(opts)
	if err != nil {
		return nil, err
	}
	for i := range cat {
		if strings.EqualFold(cat[i].ID, id) {
			return &cat[i], nil
		}
	}
	return nil, fmt.Errorf("rule %q not found: %w", id, os.ErrNotExist)
}

// fromCompiledRule projects a compiled YAML rule into the catalog
// shape. Patterns are pre-formatted with the "[regex] ..." /
// "[contains] ..." prefix the existing CLI uses; doing the
// formatting here keeps explain.go free of internal/rules types.
func fromCompiledRule(r *rules.CompiledRule) rulemeta.Rule {
	patterns := make([]string, 0, len(r.Patterns))
	for _, p := range r.Patterns {
		switch p.Type {
		case rules.PatternRegex:
			patterns = append(patterns, fmt.Sprintf("[regex] %s", p.Regex.String()))
		case rules.PatternContains:
			patterns = append(patterns, fmt.Sprintf("[contains] %s", p.Value))
		}
	}
	return rulemeta.Rule{
		ID:             r.ID,
		Name:           r.Name,
		Severity:       r.Severity.String(),
		Category:       r.Category,
		Analyzer:       rulemeta.AnalyzerPattern, // empty -> JSON omits
		Description:    r.Description,
		Remediation:    r.Remediation,
		Patterns:       patterns,
		TruePositives:  r.Examples.TruePositive,
		FalsePositives: r.Examples.FalsePositive,
	}
}
