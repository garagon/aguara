package rulecatalog

import (
	"fmt"
	"sort"
	"strings"

	"github.com/garagon/aguara/internal/engine"
	"github.com/garagon/aguara/internal/rulemeta"
	"github.com/garagon/aguara/internal/rules"
	"github.com/garagon/aguara/internal/rules/builtin"
	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
)

// Ref names a rule ID together with the configuration input that named it.
type Ref struct {
	ID     string
	Source string
}

// OverrideRef is a per-rule override together with the input that supplied it.
type OverrideRef struct {
	ID       string
	Source   string
	Override rules.RuleOverride
}

// Input is caller-supplied rule configuration before validation. The CLI and
// the library describe their configuration with it so both validate the same
// way; only what they do with the problems differs.
type Input struct {
	// CustomRulesDirs are loaded in order after the built-in rules.
	CustomRulesDirs []string
	// Disabled lists rule IDs to suppress.
	Disabled []Ref
	// Overrides lists per-rule overrides. Order matters only for problems
	// and for two keys that name the same rule; callers that start from a
	// map should sort the keys.
	Overrides []OverrideRef
	// Enforced lists the rule IDs the content-aware and minimal scan
	// profiles keep enforcing.
	Enforced []Ref
}

// Resolution is validated rule configuration, ready to build a scanner or a
// catalog from.
type Resolution struct {
	// Compiled holds the pattern rules that will run: built-in rules and
	// custom rules that compiled and do not reuse an existing ID, with
	// severity overrides applied and disabled rules removed.
	Compiled []*rules.CompiledRule
	// Disabled lists the canonical (upper-case) IDs to suppress, sorted.
	Disabled []string
	// Enforced lists the canonical IDs the relaxed scan profiles keep
	// enforcing, sorted.
	Enforced []string
	// Overrides holds the accepted overrides keyed by canonical rule ID.
	// Severity is canonical ("HIGH"); an invalid severity is cleared and
	// reported.
	Overrides map[string]rules.RuleOverride
	// Problems lists every input that was skipped or ignored, in the order
	// it was found. An empty list means the configuration is valid.
	Problems []types.ConfigProblem
}

// builtinSource labels problems in embedded rules. Built-in rules are tested
// to compile, so this should never appear in practice.
const builtinSource = "built-in rules"

// CanonicalID is the form rule IDs are compared in: trimmed and upper-case.
func CanonicalID(id string) string {
	return strings.ToUpper(strings.TrimSpace(id))
}

// Resolve loads the built-in rules and the custom rule directories, compiles
// them, and validates the disable list, the overrides and the profile
// enforcement list against the resulting catalog (pattern rules plus
// analyzer-emitted rules).
//
// Problems with individual inputs do not stop resolution: the offending input
// is skipped (a rule that does not compile, a custom rule that reuses an ID,
// an unknown rule ID) or ignored (an invalid override severity), and the
// problem is recorded in Resolution.Problems. Callers decide whether problems
// are fatal. The returned error is reserved for failures that leave nothing
// to validate: a custom rules directory that cannot be read, or a rule file
// that is not valid YAML.
func Resolve(in Input) (*Resolution, error) {
	res := &Resolution{Overrides: map[string]rules.RuleOverride{}}
	addProblem := func(kind types.ConfigProblemKind, ruleID, source, format string, args ...any) {
		res.Problems = append(res.Problems, types.ConfigProblem{
			Kind:    kind,
			RuleID:  ruleID,
			Source:  source,
			Message: fmt.Sprintf(format, args...),
		})
	}

	builtinRaw, err := rules.LoadFromFS(builtin.FS())
	if err != nil {
		return nil, fmt.Errorf("loading built-in rules: %w", err)
	}

	// known maps every defined ID to where it was defined, for duplicate
	// detection and for validating references.
	known := map[string]string{}
	var accepted []*rules.CompiledRule
	for _, raw := range builtinRaw {
		cr, err := rules.Compile(raw)
		if err != nil {
			addProblem(types.ConfigProblemInvalidRule, raw.ID, builtinSource, "%v", err)
			continue
		}
		known[CanonicalID(cr.ID)] = builtinSource
		accepted = append(accepted, cr)
	}
	for _, meta := range engine.RuleMetadata() {
		known[CanonicalID(meta.ID)] = builtinSource
	}

	for _, dir := range rules.UniqueDirs(in.CustomRulesDirs) {
		custom, skipped, err := rules.LoadFromDir(dir)
		if err != nil {
			return nil, fmt.Errorf("loading custom rules from %s: %w", dir, err)
		}
		for _, s := range skipped {
			addProblem(types.ConfigProblemInvalidRule, "", s.Path, "%s", s.Reason)
		}
		for _, raw := range custom {
			cr, err := rules.Compile(raw)
			if err != nil {
				addProblem(types.ConfigProblemInvalidRule, raw.ID, raw.Source, "%v", err)
				continue
			}
			id := CanonicalID(cr.ID)
			if where, dup := known[id]; dup {
				if where == builtinSource {
					addProblem(types.ConfigProblemDuplicateRuleID, cr.ID, raw.Source,
						"rule ID %s is already used by a built-in rule; choose a different ID", cr.ID)
				} else {
					addProblem(types.ConfigProblemDuplicateRuleID, cr.ID, raw.Source,
						"rule ID %s is already defined in %s", cr.ID, where)
				}
				continue
			}
			known[id] = raw.Source
			accepted = append(accepted, cr)
		}
	}

	overrideKey := map[string]string{}
	for _, o := range in.Overrides {
		id := CanonicalID(o.ID)
		if id == "" {
			addProblem(types.ConfigProblemUnknownRuleID, o.ID, o.Source, "override has an empty rule ID")
			continue
		}
		if _, ok := known[id]; !ok {
			addProblem(types.ConfigProblemUnknownRuleID, o.ID, o.Source, "unknown rule ID %q", o.ID)
			continue
		}
		if first, dup := overrideKey[id]; dup {
			addProblem(types.ConfigProblemConflictingOverride, o.ID, o.Source,
				"rule %s has more than one override (%q and %q)", id, first, o.ID)
			continue
		}
		overrideKey[id] = o.ID
		ovr := o.Override
		if len(ovr.ApplyToTools) > 0 && len(ovr.ExemptTools) > 0 {
			addProblem(types.ConfigProblemConflictingOverride, o.ID, o.Source,
				"rule %s: apply_to_tools and exempt_tools are mutually exclusive", o.ID)
			// Tool scoping has always used ApplyToTools when both are set.
			ovr.ExemptTools = nil
		}
		if ovr.Severity != "" {
			sev, err := types.ParseSeverity(ovr.Severity)
			if err != nil {
				addProblem(types.ConfigProblemInvalidSeverity, o.ID, o.Source,
					"rule %s: invalid severity %q (use critical, high, medium, low or info)", o.ID, ovr.Severity)
				ovr.Severity = ""
			} else {
				ovr.Severity = sev.String()
			}
		}
		res.Overrides[id] = ovr
	}

	disabled := map[string]bool{}
	for _, ref := range in.Disabled {
		id := CanonicalID(ref.ID)
		if id == "" {
			continue // empty list entries have always been ignored
		}
		if _, ok := known[id]; !ok {
			addProblem(types.ConfigProblemUnknownRuleID, ref.ID, ref.Source, "unknown rule ID %q", ref.ID)
			continue
		}
		disabled[id] = true
	}
	// A Disabled override suppresses the rule like the disable list does,
	// whichever engine emits it.
	for id, ovr := range res.Overrides {
		if ovr.Disabled {
			disabled[id] = true
		}
	}
	for id := range disabled {
		res.Disabled = append(res.Disabled, id)
	}
	sort.Strings(res.Disabled)

	enforced := map[string]bool{}
	for _, ref := range in.Enforced {
		id := CanonicalID(ref.ID)
		if id == "" {
			continue
		}
		if _, ok := known[id]; !ok {
			addProblem(types.ConfigProblemUnknownRuleID, ref.ID, ref.Source, "unknown rule ID %q", ref.ID)
			continue
		}
		// A disabled rule never produces a finding, so enforcing it would
		// silently enforce nothing. A caller that forwards a user-supplied
		// disable list must not let it switch off an enforced rule without
		// a signal. The rule stays disabled and the entry is not enforced.
		if disabled[id] {
			addProblem(types.ConfigProblemConflictingOverride, ref.ID, ref.Source,
				"rule %s is both disabled and enforced by the scan profile", id)
			continue
		}
		if !enforced[id] {
			enforced[id] = true
			res.Enforced = append(res.Enforced, id)
		}
	}
	sort.Strings(res.Enforced)

	for _, cr := range accepted {
		id := CanonicalID(cr.ID)
		if disabled[id] {
			continue
		}
		if ovr, ok := res.Overrides[id]; ok && ovr.Severity != "" {
			sev, _ := types.ParseSeverity(ovr.Severity) // validated above
			cr.Severity = sev
		}
		res.Compiled = append(res.Compiled, cr)
	}
	return res, nil
}

// SeverityOverrides returns the accepted severity overrides keyed by
// canonical rule ID, for every kind of rule. Pattern rules already carry
// theirs in Compiled; the scanner applies the map to every finding so that
// analyzer-emitted rules honour the same override (scanner.SetSeverityOverrides).
func (r *Resolution) SeverityOverrides() map[string]types.Severity {
	var out map[string]types.Severity
	for id, ovr := range r.Overrides {
		if ovr.Severity == "" {
			continue
		}
		sev, err := types.ParseSeverity(ovr.Severity)
		if err != nil {
			continue // cleared during Resolve; defensive only
		}
		if out == nil {
			out = make(map[string]types.Severity)
		}
		out[id] = sev
	}
	return out
}

// ToolScopedRules returns the accepted overrides that restrict a rule to, or
// exempt it from, specific tools, keyed by canonical rule ID.
func (r *Resolution) ToolScopedRules() map[string]scanner.ToolScopedRule {
	var out map[string]scanner.ToolScopedRule
	for id, ovr := range r.Overrides {
		if len(ovr.ApplyToTools) == 0 && len(ovr.ExemptTools) == 0 {
			continue
		}
		if out == nil {
			out = make(map[string]scanner.ToolScopedRule)
		}
		out[id] = scanner.ToolScopedRule{ApplyToTools: ovr.ApplyToTools, ExemptTools: ovr.ExemptTools}
	}
	return out
}

// Catalog returns the merged catalog for this resolution, filtered by
// category when category is non-empty.
func (r *Resolution) Catalog(category string) []rulemeta.Rule {
	overrides := make(map[string]Override, len(r.Overrides))
	for id, ovr := range r.Overrides {
		overrides[id] = Override{Severity: ovr.Severity, Disabled: ovr.Disabled}
	}
	return FromCompiled(r.Compiled, Options{
		DisableRuleIDs: r.Disabled,
		Overrides:      overrides,
		Category:       category,
	})
}
