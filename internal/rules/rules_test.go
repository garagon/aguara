package rules_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/engine/pattern"
	"github.com/garagon/aguara/internal/rules"
	"github.com/garagon/aguara/internal/rules/builtin"
	"github.com/garagon/aguara/internal/scanner"
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

func TestCompileTargetNegation(t *testing.T) {
	// `!`-prefixed targets are split into ExcludeTargets; positive globs
	// stay in Targets. Order between positive and negative is irrelevant.
	raw := rules.RawRule{
		ID:        "TEST_NEG",
		Name:      "Negation",
		Severity:  "HIGH",
		Category:  "test",
		MatchMode: "any",
		Targets:   []string{"*.json", "!package.json", "*.yaml", "!"},
		Patterns:  []rules.RawPattern{{Type: rules.PatternContains, Value: "x"}},
	}
	compiled, err := rules.Compile(raw)
	require.NoError(t, err)
	require.Equal(t, []string{"*.json", "*.yaml"}, compiled.Targets)
	// bare "!" is ignored (no filename), only "package.json" is excluded.
	require.Equal(t, []string{"package.json"}, compiled.ExcludeTargets)
}

func TestCompileNoNegationUnchanged(t *testing.T) {
	// A rule with no `!` entries keeps Targets intact and has no exclusions.
	raw := rules.RawRule{
		ID:        "TEST_PLAIN",
		Name:      "Plain",
		Severity:  "HIGH",
		Category:  "test",
		MatchMode: "any",
		Targets:   []string{"*.json", "*.yaml"},
		Patterns:  []rules.RawPattern{{Type: rules.PatternContains, Value: "x"}},
	}
	compiled, err := rules.Compile(raw)
	require.NoError(t, err)
	require.Equal(t, []string{"*.json", "*.yaml"}, compiled.Targets)
	require.Empty(t, compiled.ExcludeTargets)
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

func TestCompileExcludeScope(t *testing.T) {
	compile := func(scope string) (*rules.CompiledRule, error) {
		return rules.Compile(rules.RawRule{
			ID: "TEST_SCOPE", Name: "Scope", Severity: "LOW", Category: "test",
			Patterns:        []rules.RawPattern{{Type: rules.PatternContains, Value: "x"}},
			ExcludePatterns: []rules.RawExcludePattern{{Type: rules.PatternContains, Value: "y", Scope: scope}},
		})
	}
	for scope, want := range map[string]rules.ExcludeScope{
		"":        rules.ExcludeScopeLine,
		"line":    rules.ExcludeScopeLine,
		"context": rules.ExcludeScopeContext,
		"Context": rules.ExcludeScopeContext,
	} {
		compiled, err := compile(scope)
		require.NoError(t, err, scope)
		require.Equal(t, want, compiled.ExcludePatterns[0].Scope, scope)
	}
	_, err := compile("section")
	require.ErrorContains(t, err, "unknown scope")
}

func TestLoadExcludeScopeFromYAML(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "r.yaml"), []byte(`id: TEST_YAML_SCOPE
name: Scope
severity: LOW
category: test
patterns:
  - type: contains
    value: x
exclude_patterns:
  - type: contains
    value: plain
  - type: contains
    value: heading
    scope: context
`), 0o600))
	raws, err := rules.LoadFromDir(dir)
	require.NoError(t, err)
	compiled, errs := rules.CompileAll(raws)
	require.Empty(t, errs)
	require.Len(t, compiled, 1)
	require.Equal(t, rules.ExcludeScopeLine, compiled[0].ExcludePatterns[0].Scope)
	require.Equal(t, rules.ExcludeScopeContext, compiled[0].ExcludePatterns[1].Scope)

	// scope is an exclude-only key; a positive pattern rejects it.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "r.yaml"), []byte(`id: TEST_YAML_SCOPE
name: Scope
severity: LOW
category: test
patterns:
  - type: contains
    value: x
    scope: context
`), 0o600))
	_, err = rules.LoadFromDir(dir)
	require.Error(t, err)
}

func TestCompileWithinLines(t *testing.T) {
	raw := func(mode string, within int) rules.RawRule {
		return rules.RawRule{
			ID: "TEST_WITHIN", Name: "Within", Severity: "LOW", Category: "test", MatchMode: mode, WithinLines: within,
			Patterns: []rules.RawPattern{{Type: rules.PatternContains, Value: "a"}, {Type: rules.PatternContains, Value: "b"}},
		}
	}
	compiled, err := rules.Compile(raw("all", 5))
	require.NoError(t, err)
	require.Equal(t, 5, compiled.WithinLines)

	compiled, err = rules.Compile(raw("all", 0))
	require.NoError(t, err)
	require.Zero(t, compiled.WithinLines)

	_, err = rules.Compile(raw("any", 5))
	require.ErrorContains(t, err, "within_lines requires match_mode: all")
	_, err = rules.Compile(raw("", 5))
	require.ErrorContains(t, err, "within_lines requires match_mode: all")
	_, err = rules.Compile(raw("all", -1))
	require.ErrorContains(t, err, "within_lines must be positive")

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "r.yaml"), []byte(`id: TEST_YAML_WITHIN
name: Within
severity: LOW
category: test
match_mode: all
within_lines: 4
patterns:
  - type: contains
    value: a
  - type: contains
    value: b
`), 0o600))
	raws, err := rules.LoadFromDir(dir)
	require.NoError(t, err)
	require.Equal(t, 4, raws[0].WithinLines)
}

// Every built-in within_lines rule uses match_mode: all (Compile enforces
// it) and carries a false_positive whose patterns are farther apart than
// the window, so the bound stays exercised by the self-test.
func TestBuiltinWithinLinesRulesHaveWindowExamples(t *testing.T) {
	rawRules, err := rules.LoadFromFS(builtin.FS())
	require.NoError(t, err)
	compiled, errs := rules.CompileAll(rawRules)
	require.Empty(t, errs)
	matcher := pattern.NewMatcher(compiled)
	bounded := 0
	for _, rule := range compiled {
		if rule.WithinLines == 0 {
			continue
		}
		bounded++
		whole := *rule
		whole.WithinLines = 0
		wholeMatcher := pattern.NewMatcher([]*rules.CompiledRule{&whole})
		exercised := false
		for _, fp := range rule.Examples.FalsePositive {
			if matchesRule(t, wholeMatcher, &whole, fp) && !matchesRule(t, matcher, rule, fp) {
				exercised = true
			}
		}
		require.Truef(t, exercised, "rule %s: no false_positive example shows the within_lines bound", rule.ID)

		// Rules that describe an action chain use a wide window so ordinary
		// layouts (numbered steps with blank lines, a heredoc between a
		// download and chmod, a multi-line manifest) still match. Each such
		// rule keeps a true_positive whose halves a 5-line window would miss.
		if rule.WithinLines > 5 {
			narrow := *rule
			narrow.WithinLines = 5
			narrowMatcher := pattern.NewMatcher([]*rules.CompiledRule{&narrow})
			spread := false
			for _, tp := range rule.Examples.TruePositive {
				if !matchesRule(t, narrowMatcher, &narrow, tp) {
					spread = true
				}
			}
			require.Truef(t, spread, "rule %s: no true_positive spreads its evidence beyond 5 lines", rule.ID)
		}
	}
	require.NotZero(t, bounded)
}

func TestCompileInvalidRegex(t *testing.T) {
	raw := rules.RawRule{
		ID:       "TEST_003",
		Name:     "Bad Regex",
		Category: "test",
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

// TestSensitiveFlag_MCPCFG003 pins that MCPCFG_003 carries the
// sensitive flag through YAML -> compiled rule. The rule's `match_mode:
// all` requires both the env-block pattern AND the secret-bearing
// key/value pattern to fire, so the resulting MatchedText literally
// contains the value side of the env binding. Without the flag,
// types.RedactSensitiveFindings does not scrub that text and the
// value flows un-redacted into JSON / SARIF / terminal output. Peer
// rules with the same shape (MCP_007, all CRED_* via category) set
// this; MCPCFG_003 was missed in the original sensitive-flag rollout
// and is restored here.
func TestSensitiveFlag_MCPCFG003(t *testing.T) {
	rawRules, err := rules.LoadFromFS(builtin.FS())
	require.NoError(t, err)
	compiled, errs := rules.CompileAll(rawRules)
	require.Empty(t, errs)

	var rule *rules.CompiledRule
	for i := range compiled {
		if compiled[i].ID == "MCPCFG_003" {
			rule = compiled[i]
			break
		}
	}
	require.NotNil(t, rule, "MCPCFG_003 not found in built-in rules")
	require.True(t, rule.Sensitive,
		"MCPCFG_003 must be sensitive: true; otherwise its matched_text flows un-redacted through output formatters")
}

func TestLoadBuiltinRules(t *testing.T) {
	rawRules, err := rules.LoadFromFS(builtin.FS())
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(rawRules), 70, "expected at least 70 built-in rules")

	compiled, errs := rules.CompileAll(rawRules)
	require.Empty(t, errs, "all built-in rules should compile without errors")
	require.GreaterOrEqual(t, len(compiled), 70)
}

// TestRuleSelfTest runs every built-in rule's examples through the
// production pattern matcher, so an example is judged exactly as a scanned
// file would be: per-line exclude scopes, match_mode, within_lines windows
// and target dispatch all apply. An example may span several lines (YAML
// "\n" escapes or a block scalar); its line numbers are those of the
// example text, which lets a rule pin down, for instance, that a comment
// line above a match does not suppress it.
func TestRuleSelfTest(t *testing.T) {
	rawRules, err := rules.LoadFromFS(builtin.FS())
	require.NoError(t, err)

	compiled, errs := rules.CompileAll(rawRules)
	require.Empty(t, errs)

	matcher := pattern.NewMatcher(compiled)
	for _, rule := range compiled {
		t.Run(rule.ID, func(t *testing.T) {
			// Test true positives
			for _, tp := range rule.Examples.TruePositive {
				matched := matchesRule(t, matcher, rule, tp)
				require.Truef(t, matched,
					"rule %s: true_positive not matched: %q", rule.ID, tp)
			}
			// Test false positives
			for _, fp := range rule.Examples.FalsePositive {
				matched := matchesRule(t, matcher, rule, fp)
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

func TestFilterByIDsCaseInsensitive(t *testing.T) {
	compiled := makeTestRules("custom_Mixed_001", "KEEP_001")
	disabled := map[string]bool{"CUSTOM_mixed_001": true}
	result := rules.FilterByIDs(compiled, disabled)
	require.Len(t, result, 1)
	require.Equal(t, "KEEP_001", result[0].ID)
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

// matchesRule reports whether scanning text as a file the rule targets
// yields a finding for that rule. Findings recovered by the decoder pass
// are ignored: examples describe what the rule matches in plain text.
func matchesRule(t *testing.T, matcher *pattern.Matcher, rule *rules.CompiledRule, text string) bool {
	t.Helper()
	findings, err := matcher.Analyze(context.Background(), &scanner.Target{
		RelPath: selfTestPath(rule),
		Content: []byte(text),
	})
	require.NoError(t, err)
	for _, f := range findings {
		if f.RuleID == rule.ID && f.Analyzer == "pattern" {
			return true
		}
	}
	return false
}

// selfTestPath returns a file name the rule targets: its first target
// glob made concrete ("*.json" -> "selftest.json", a literal file name as
// is), or a plain text file for rules that apply to every file.
func selfTestPath(rule *rules.CompiledRule) string {
	if len(rule.Targets) == 0 {
		return "selftest.txt"
	}
	target := rule.Targets[0]
	if strings.HasPrefix(target, "*.") {
		return "selftest" + target[1:]
	}
	return target
}
