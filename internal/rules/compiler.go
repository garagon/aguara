package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/garagon/aguara/internal/types"
)

// Compile converts a RawRule into a CompiledRule ready for execution.
func Compile(raw RawRule) (*CompiledRule, error) {
	if raw.ID == "" {
		return nil, fmt.Errorf("rule missing ID")
	}
	if len(raw.Patterns) == 0 {
		return nil, fmt.Errorf("rule %s: no patterns defined", raw.ID)
	}

	sev, err := types.ParseSeverity(raw.Severity)
	if err != nil {
		return nil, fmt.Errorf("rule %s: %w", raw.ID, err)
	}

	mode := MatchAny
	if strings.ToLower(raw.MatchMode) == "all" {
		mode = MatchAll
	}

	compiled := &CompiledRule{
		ID:          raw.ID,
		Name:        raw.Name,
		Description: raw.Description,
		Severity:    sev,
		Category:    raw.Category,
		Targets:     raw.Targets,
		MatchMode:   mode,
		Examples:    raw.Examples,
	}

	for i, p := range raw.Patterns {
		cp, err := compilePattern(p)
		if err != nil {
			return nil, fmt.Errorf("rule %s pattern %d: %w", raw.ID, i, err)
		}
		compiled.Patterns = append(compiled.Patterns, cp)
	}

	for i, p := range raw.ExcludePatterns {
		cp, err := compilePattern(p)
		if err != nil {
			return nil, fmt.Errorf("rule %s exclude_pattern %d: %w", raw.ID, i, err)
		}
		compiled.ExcludePatterns = append(compiled.ExcludePatterns, cp)
	}

	return compiled, nil
}

func compilePattern(p RawPattern) (CompiledPattern, error) {
	cp := CompiledPattern{Type: p.Type, Value: p.Value}
	switch p.Type {
	case PatternRegex:
		re, err := regexp.Compile(p.Value)
		if err != nil {
			return cp, fmt.Errorf("invalid regex: %w", err)
		}
		cp.Regex = re
	case PatternContains:
		cp.Value = strings.ToLower(p.Value)
	default:
		return cp, fmt.Errorf("unknown type %q", p.Type)
	}
	return cp, nil
}

// CompileAll compiles a slice of raw rules, returning compiled rules and any errors.
func CompileAll(raws []RawRule) ([]*CompiledRule, []error) {
	var rules []*CompiledRule
	var errs []error
	for _, raw := range raws {
		cr, err := Compile(raw)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		rules = append(rules, cr)
	}
	return rules, errs
}

// RuleOverride allows per-rule severity change or disable from config.
type RuleOverride struct {
	Severity string
	Disabled bool
}

// ApplyOverrides applies config-based rule overrides to compiled rules.
// Disabled rules are removed. Severity overrides update the rule's severity.
// Invalid severity values produce an error but keep the original rule.
func ApplyOverrides(compiled []*CompiledRule, overrides map[string]RuleOverride) ([]*CompiledRule, []error) {
	var result []*CompiledRule
	var errs []error
	for _, rule := range compiled {
		ovr, ok := overrides[rule.ID]
		if !ok {
			result = append(result, rule)
			continue
		}
		if ovr.Disabled {
			continue
		}
		if ovr.Severity != "" {
			sev, err := types.ParseSeverity(ovr.Severity)
			if err != nil {
				errs = append(errs, fmt.Errorf("rule %s override: %w", rule.ID, err))
				result = append(result, rule)
				continue
			}
			rule.Severity = sev
		}
		result = append(result, rule)
	}
	return result, errs
}

// FilterByIDs removes rules whose IDs are in the disabled set.
func FilterByIDs(compiled []*CompiledRule, disabled map[string]bool) []*CompiledRule {
	var result []*CompiledRule
	for _, rule := range compiled {
		if !disabled[rule.ID] {
			result = append(result, rule)
		}
	}
	return result
}
