package rules_test

import (
	"testing"

	"github.com/garagon/aguara/internal/rules"
	"github.com/garagon/aguara/internal/rules/builtin"
	"github.com/garagon/aguara/internal/types"
	"github.com/stretchr/testify/require"
)

func TestCompileValidRule(t *testing.T) {
	raw := rules.RawRule{
		ID:        "TEST_001",
		Name:      "Test Rule",
		Severity:  "HIGH",
		Category:  "test",
		MatchMode: "any",
		Patterns: []rules.RawPattern{
			{Type: rules.PatternRegex, Value: "(?i)test\\s+pattern"},
			{Type: rules.PatternContains, Value: "hello world"},
		},
	}

	compiled, err := rules.Compile(raw)
	require.NoError(t, err)
	require.Equal(t, "TEST_001", compiled.ID)
	require.Equal(t, types.SeverityHigh, compiled.Severity)
	require.Equal(t, rules.MatchAny, compiled.MatchMode)
	require.Len(t, compiled.Patterns, 2)
	require.NotNil(t, compiled.Patterns[0].Regex)
	require.Equal(t, "hello world", compiled.Patterns[1].Value) // lowercased
}

func TestCompileMatchAll(t *testing.T) {
	raw := rules.RawRule{
		ID:        "TEST_002",
		Name:      "Match All",
		Severity:  "MEDIUM",
		Category:  "test",
		MatchMode: "all",
		Patterns: []rules.RawPattern{
			{Type: rules.PatternContains, Value: "pattern1"},
			{Type: rules.PatternContains, Value: "pattern2"},
		},
	}

	compiled, err := rules.Compile(raw)
	require.NoError(t, err)
	require.Equal(t, rules.MatchAll, compiled.MatchMode)
}

func TestCompileInvalidRegex(t *testing.T) {
	raw := rules.RawRule{
		ID:       "TEST_003",
		Name:     "Bad Regex",
		Severity: "LOW",
		Patterns: []rules.RawPattern{
			{Type: rules.PatternRegex, Value: "[invalid"},
		},
	}

	_, err := rules.Compile(raw)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid regex")
}

func TestCompileMissingID(t *testing.T) {
	raw := rules.RawRule{
		Severity: "LOW",
		Patterns: []rules.RawPattern{{Type: rules.PatternContains, Value: "x"}},
	}
	_, err := rules.Compile(raw)
	require.Error(t, err)
}

func TestLoadBuiltinRules(t *testing.T) {
	rawRules, err := rules.LoadFromFS(builtin.FS())
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(rawRules), 70, "expected at least 70 built-in rules")

	compiled, errs := rules.CompileAll(rawRules)
	require.Empty(t, errs, "all built-in rules should compile without errors")
	require.GreaterOrEqual(t, len(compiled), 70)
}

func TestRuleSelfTest(t *testing.T) {
	rawRules, err := rules.LoadFromFS(builtin.FS())
	require.NoError(t, err)

	compiled, errs := rules.CompileAll(rawRules)
	require.Empty(t, errs)

	for _, rule := range compiled {
		t.Run(rule.ID, func(t *testing.T) {
			// Test true positives
			for _, tp := range rule.Examples.TruePositive {
				matched := matchesRule(rule, tp)
				require.Truef(t, matched,
					"rule %s: true_positive not matched: %q", rule.ID, tp)
			}
			// Test false positives
			for _, fp := range rule.Examples.FalsePositive {
				matched := matchesRule(rule, fp)
				require.Falsef(t, matched,
					"rule %s: false_positive incorrectly matched: %q", rule.ID, fp)
			}
		})
	}
}

func TestApplyOverridesDisabled(t *testing.T) {
	compiled := makeTestRules("R1", "R2", "R3")
	overrides := map[string]rules.RuleOverride{
		"R2": {Disabled: true},
	}
	result, errs := rules.ApplyOverrides(compiled, overrides)
	require.Empty(t, errs)
	require.Len(t, result, 2)
	require.Equal(t, "R1", result[0].ID)
	require.Equal(t, "R3", result[1].ID)
}

func TestApplyOverridesSeverity(t *testing.T) {
	compiled := makeTestRules("R1")
	compiled[0].Severity = types.SeverityHigh
	overrides := map[string]rules.RuleOverride{
		"R1": {Severity: "LOW"},
	}
	result, errs := rules.ApplyOverrides(compiled, overrides)
	require.Empty(t, errs)
	require.Len(t, result, 1)
	require.Equal(t, types.SeverityLow, result[0].Severity)
}

func TestApplyOverridesInvalidSeverity(t *testing.T) {
	compiled := makeTestRules("R1")
	compiled[0].Severity = types.SeverityHigh
	overrides := map[string]rules.RuleOverride{
		"R1": {Severity: "BANANA"},
	}
	result, errs := rules.ApplyOverrides(compiled, overrides)
	require.Len(t, errs, 1)
	require.Contains(t, errs[0].Error(), "BANANA")
	require.Len(t, result, 1)
	require.Equal(t, types.SeverityHigh, result[0].Severity) // original kept
}

func TestApplyOverridesNoMatch(t *testing.T) {
	compiled := makeTestRules("R1", "R2")
	overrides := map[string]rules.RuleOverride{
		"UNKNOWN": {Disabled: true},
	}
	result, errs := rules.ApplyOverrides(compiled, overrides)
	require.Empty(t, errs)
	require.Len(t, result, 2)
}

func TestFilterByIDs(t *testing.T) {
	compiled := makeTestRules("R1", "R2", "R3")
	disabled := map[string]bool{"R2": true}
	result := rules.FilterByIDs(compiled, disabled)
	require.Len(t, result, 2)
	require.Equal(t, "R1", result[0].ID)
	require.Equal(t, "R3", result[1].ID)
}

func TestFilterByIDsEmpty(t *testing.T) {
	compiled := makeTestRules("R1", "R2", "R3")
	disabled := map[string]bool{}
	result := rules.FilterByIDs(compiled, disabled)
	require.Len(t, result, 3)
}

func makeTestRules(ids ...string) []*rules.CompiledRule {
	var result []*rules.CompiledRule
	for _, id := range ids {
		result = append(result, &rules.CompiledRule{
			ID:       id,
			Name:     "Test " + id,
			Severity: types.SeverityMedium,
			Category: "test",
		})
	}
	return result
}

// matchesRule checks if text triggers the rule, respecting match_mode.
func matchesRule(rule *rules.CompiledRule, text string) bool {
	switch rule.MatchMode {
	case rules.MatchAll:
		// All patterns must match
		for _, pat := range rule.Patterns {
			if !patternMatches(pat, text) {
				return false
			}
		}
		if isExcludedText(rule.ExcludePatterns, text) {
			return false
		}
		return true
	default: // MatchAny
		// Any pattern triggers, but check excludes per line
		for _, pat := range rule.Patterns {
			if patternMatches(pat, text) {
				if !isExcludedText(rule.ExcludePatterns, text) {
					return true
				}
			}
		}
		return false
	}
}

// isExcludedText checks if any line in the text matches an exclude pattern.
func isExcludedText(excludes []rules.CompiledPattern, text string) bool {
	for _, ep := range excludes {
		if patternMatches(ep, text) {
			return true
		}
	}
	return false
}

func patternMatches(pat rules.CompiledPattern, text string) bool {
	switch pat.Type {
	case rules.PatternRegex:
		return pat.Regex != nil && pat.Regex.MatchString(text)
	case rules.PatternContains:
		return len(pat.Value) > 0 && contains(toLower(text), pat.Value)
	}
	return false
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := range len(s) {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		} else {
			b[i] = c
		}
	}
	return string(b)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
