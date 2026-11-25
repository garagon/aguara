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
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/garagon/aguara/internal/engine"
	"github.com/garagon/aguara/internal/rulemeta"
	"github.com/garagon/aguara/internal/rules"
	"github.com/garagon/aguara/internal/types"
)

// Options controls Build. All fields are optional; the zero value
// builds the full catalog (every YAML rule + every analyzer rule).
type Options struct {
	// CustomRulesDirs loads additional YAML rules from each directory,
	// in order, and merges them in. Matches the repeatable --rules flag
	// and repeated aguara.WithCustomRules options.
	CustomRulesDirs []string
	// DisableRuleIDs filters by exact ID match before returning.
	// Matches the --disable-rule CLI flag and the config-file
	// disable_rules list.
	DisableRuleIDs []string
	// Overrides apply per-rule severity changes and disables, the
	// same surface aguara.WithRuleOverrides exposes, to pattern and
	// analyzer rules alike. Keyed by rule ID (case-insensitive). An
	// entry with Disabled=true drops the rule; an entry with a
	// non-empty Severity replaces the metadata's severity in the
	// output. Mirrors the scanner's override path so a policy UI
	// built on Build agrees with what the scanner actually runs.
	Overrides map[string]Override
	// Category, when non-empty, filters the result to rules whose
	// Category matches case-insensitively.
	Category string
	// Warn receives the configuration problems Build skipped (see
	// Resolve). nil discards them.
	Warn func(format string, args ...any)
}

// Override is the catalog-side projection of aguara.RuleOverride.
// Kept here so the catalog package does not import the public
// aguara API (which would create a cycle). The fields are a
// strict subset: tool-scoping (ApplyToTools / ExemptTools) is a
// scanner concern and does not change what list-rules / explain
// show, so it is intentionally omitted from this struct.
type Override struct {
	Severity string // empty -> keep the catalog metadata severity
	Disabled bool   // true  -> drop the rule from list-rules output
}

// Build returns the merged catalog. Configuration problems (a custom rule
// that does not compile or reuses an existing ID, an unknown ID in
// DisableRuleIDs or Overrides, an invalid override severity) are skipped and
// passed to Warn; callers that must reject them use Resolve directly. The
// error is reserved for custom rules directories that cannot be loaded
// (missing directory, malformed YAML); built-in rules are embedded and
// always load.
//
// Returned slice is sorted by ID so the CLI output is stable
// across runs.
func Build(opts Options) ([]rulemeta.Rule, error) {
	res, err := Resolve(opts.input())
	if err != nil {
		return nil, fmt.Errorf("rulecatalog: %w", err)
	}
	if opts.Warn != nil {
		for _, p := range res.Problems {
			opts.Warn("warning: %s\n", p)
		}
	}
	return res.Catalog(opts.Category), nil
}

// input describes Options as a Resolve input. Map keys are sorted so the
// result does not depend on map iteration order.
func (opts Options) input() Input {
	in := Input{CustomRulesDirs: opts.CustomRulesDirs}
	for _, id := range opts.DisableRuleIDs {
		in.Disabled = append(in.Disabled, Ref{ID: id, Source: "disable list"})
	}
	ids := make([]string, 0, len(opts.Overrides))
	for id := range opts.Overrides {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		o := opts.Overrides[id]
		in.Overrides = append(in.Overrides, OverrideRef{
			ID:       id,
			Source:   "overrides",
			Override: rules.RuleOverride{Severity: o.Severity, Disabled: o.Disabled},
		})
	}
	return in
}

// FromCompiled builds the merged catalog from an already-compiled pattern
// rule set. Reusable scanners call this after loadAndCompile so their
// ListRules and ExplainRule methods include analyzer-owned rules without
// loading and compiling the YAML catalog a second time.
//
// CustomRulesDirs and Warn are ignored because loading and compilation have
// already happened. DisableRuleIDs, Overrides, and Category are still applied
// to the supplied rules and analyzer metadata.
func FromCompiled(compiled []*rules.CompiledRule, opts Options) []rulemeta.Rule {
	// 1. Convert compiled YAML rules into the catalog shape.
	out := make([]rulemeta.Rule, 0, len(compiled)+32)
	for _, r := range compiled {
		out = append(out, fromCompiledRule(r))
	}

	// 2. Analyzer-emitted rules, aggregated by the engine registry
	// (the same single source of truth the scanner pipelines register
	// from). Order doesn't matter; the sort at the end establishes the
	// canonical ordering. rugpull is in the catalog unconditionally
	// even though the analyzer only runs with --monitor / WithStateDir,
	// so `aguara explain RUGPULL_001` works without first enabling the
	// detector.
	out = append(out, engine.RuleMetadata()...)

	// 3. Apply the product-level decision impact after both catalog sources
	// are merged. Custom rules default to review unless Aguara explicitly
	// classifies their stable ID as supporting context.
	for i := range out {
		out[i].DecisionImpact = rulemeta.DecisionImpactFor(out[i].ID)
	}

	// 4. --disable-rule filter. Applied AFTER merge so users can
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

	// 5. Per-rule overrides: drop disabled rules and apply severity
	// overrides, for pattern and analyzer rules alike. The scanner
	// applies the same overrides to every finding (pattern rules at
	// compile time, analyzer rules through Scanner.SetSeverityOverrides
	// and the disabled-rule filter), so list-rules and explain show the
	// policy Scan enforces. Invalid severities are left unchanged here;
	// Resolve reports them.
	if len(opts.Overrides) > 0 {
		normalised := make(map[string]Override, len(opts.Overrides))
		for id, o := range opts.Overrides {
			normalised[strings.ToUpper(strings.TrimSpace(id))] = o
		}
		filtered := out[:0]
		for _, r := range out {
			ovr, ok := normalised[strings.ToUpper(r.ID)]
			if !ok {
				filtered = append(filtered, r)
				continue
			}
			if ovr.Disabled {
				continue
			}
			if ovr.Severity != "" {
				if severity, err := types.ParseSeverity(ovr.Severity); err == nil {
					r.Severity = severity.String()
				}
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
	return out
}

// ErrRuleNotFound is the sentinel FindByID returns when the
// lookup completes successfully but no rule with that ID exists.
// Distinguished from catalog-build errors (custom-rules dir
// missing, malformed YAML, ...) so callers can map a typo to a
// clean "rule X not found" message while surfacing real
// configuration problems with their full context.
var ErrRuleNotFound = errors.New("rule not found")

// FindByID returns the catalog entry with the given ID (case-
// insensitive). Used by explain.go and aguara.ExplainRule so
// both surfaces share one lookup path.
//
// Two error shapes:
//
//   - errors.Is(err, ErrRuleNotFound) -> the catalog built
//     successfully but no rule with that ID exists. Callers
//     should surface a clean "rule X not found" message.
//   - any other error -> the catalog failed to build (e.g.
//     --rules pointed at a missing directory). Callers should
//     surface the underlying error so the user can diagnose
//     the configuration problem.
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
	return nil, fmt.Errorf("rule %q: %w", id, ErrRuleNotFound)
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
		CWE:            append([]string(nil), r.CWE...),
		Patterns:       patterns,
		TruePositives:  r.Examples.TruePositive,
		FalsePositives: r.Examples.FalsePositive,
	}
}
