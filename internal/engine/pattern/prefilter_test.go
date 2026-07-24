package pattern

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/rules"
	"github.com/garagon/aguara/internal/rules/builtin"
	"github.com/garagon/aguara/internal/scanner"
	"github.com/stretchr/testify/require"
)

func TestExtractKeywords(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		want    []string
	}{
		{
			// Outer "subprocess" is required regardless of which branch of
			// (run|call|Popen) matches, so it indexes. The alternation has a
			// weak `run` branch (3 chars after the minKeywordLen filter), so
			// the alternation as a whole contributes no literals: indexing
			// "call" and "popen" would falsely filter out content matching
			// via the `run` branch.
			name:    "outer literal kept when alternation has weak branch",
			pattern: `(?i)subprocess\.(run|call|Popen)`,
			want:    []string{"subprocess"},
		},
		{
			name:    "escaped metachar",
			pattern: `(?i)\beval\s*\(`,
			want:    []string{"eval"},
		},
		{
			// Both alternations are weighed independently. (curl|wget) has
			// two strong branches, so its literals index. (bash|sh) has a
			// weak `sh` branch so the second alternation contributes nothing
			// (indexing "bash" alone would falsely filter out content like
			// `wget x | sh`).
			name:    "alternation with weak second branch drops its literals",
			pattern: `(?i)(curl|wget)\s+[^|]+\|\s*(bash|sh)\b`,
			want:    []string{"curl", "wget"},
		},
		{
			name:    "credential prefix",
			pattern: `AKIA[0-9A-Z]{16}`,
			want:    []string{"akia"},
		},
		{
			name:    "github token with underscore",
			pattern: `ghp_[a-zA-Z0-9]{36}`,
			want:    []string{"ghp_"},
		},
		{
			// `(RSA|DSA|EC|OPENSSH|PGP)?` is optional, so the regex can match
			// content without any of those literals. Even if every branch
			// were strong the group's literals would be untrustworthy as a
			// filter. Only the outer required literals contribute.
			name:    "optional alternation contributes no literals",
			pattern: `-----BEGIN\s+(RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE KEY`,
			want:    []string{"begin", "private"},
		},
		{
			name:    "no literals (all char classes and quantifiers)",
			pattern: `[A-Za-z0-9+/]{40,}={0,2}`,
			want:    nil,
		},
		{
			name:    "short literals excluded",
			pattern: `(?i)(sh|rm)\b`,
			want:    nil,
		},
		{
			// The `pwd` branch (3 chars) is weak. With no outer >=4-char
			// literal to fall back on, the whole pattern is unfilterable:
			// indexing on "password"/"passwd" would silently drop matches
			// like `pwd = secret`.
			name:    "alternation with weak branch and no outer literal is unfilterable",
			pattern: `(?i)(password|passwd|pwd)\s*[=:]`,
			want:    nil,
		},
		{
			name:    "non-capturing group handled",
			pattern: `(?:food|barn)baz`,
			want:    []string{"food", "barn"},
		},
		{
			name:    "dotted method call",
			pattern: `exec\.Command\s*\(`,
			want:    []string{"exec", "command"},
		},
		{
			name:    "URL pattern",
			pattern: `https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+`,
			want:    []string{"https", "hooks", "slack", "services"},
		},
		{
			name:    "github_pat_ with underscores",
			pattern: `github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}`,
			want:    []string{"github_pat_"},
		},
		{
			name:    "quantifier content skipped",
			pattern: `[a-z]{3,10}food`,
			want:    []string{"food"},
		},
		{
			// Regression for MCPCFG_003 ("Hardcoded secrets in MCP env
			// block"). The `API[_-]?KEY` branch yields no >=4-char literal
			// after the char-class strip (the only runs are `api` and
			// `key`, both 3 chars), so the alternation as a whole cannot
			// be trusted as a filter signal. Outer literals in the rest of
			// the pattern are all 1-char or char classes, so the entire
			// pattern is unfilterable: the rule must be marked noKeyword
			// or content with `API_KEY` would be silently skipped.
			name:    "MCPCFG_003 secret pattern is unfilterable",
			pattern: `(?i)["'][A-Z_]*(API[_-]?KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)[A-Z_]*["']\s*:\s*["'][a-zA-Z0-9_\-]{20,}["']`,
			want:    nil,
		},
		{
			// Nested alternation: inner `(A|B)` is unfilterable (both
			// branches weak). The outer alternation then has one branch
			// (`(A|B)`) with no literal, so the outer is also unfilterable.
			// With no outer literal to fall back on the pattern as a whole
			// is unfilterable.
			name:    "nested weak alternation propagates",
			pattern: `((A|B)|cdefgh)`,
			want:    nil,
		},
		{
			// Same nested-weak alternation, but now a strong outer literal
			// keeps the pattern filterable on that literal alone.
			name:    "outer literal preserved even when nested alternations collapse",
			pattern: `\bprefix\b((A|B)|cdefgh)`,
			want:    []string{"prefix"},
		},
		{
			// When the outer regex has a strong literal, an unfilterable
			// alternation does NOT poison the whole pattern. The outer
			// literal remains a valid filter.
			name:    "outer literal survives unfilterable alternation",
			pattern: `exfiltrate\s+(a|b|c)`,
			want:    []string{"exfiltrate"},
		},
		{
			// `?` on the trailing `s` makes the `s` optional, so the
			// required literal is "http", not "https". Indexing on
			// "https" would falsely filter content that matches the
			// regex via the http branch (the SSRF_002 / SSRF_006 /
			// SSRF_009 rules tripped on this in production).
			name:    "trailing ? makes preceding char optional",
			pattern: `(?i)https?://`,
			want:    []string{"http"},
		},
		{
			// Top-level alternation with a weak branch. Without the
			// pre-walk split, the walker would treat `|` as a plain
			// boundary, drop `api` (3 chars), and index "secret" alone.
			// Content matching via `api` would be falsely filtered.
			name:    "top-level alternation with weak branch is unfilterable",
			pattern: `(?i)api|secret`,
			want:    nil,
		},
		{
			// Top-level alternation, every branch strong. Both literals
			// must be indexed: content matching via either branch must
			// route to the rule.
			name:    "top-level alternation with all strong branches",
			pattern: `(?i)apikey|secret`,
			want:    []string{"apikey", "secret"},
		},
		{
			// Top-level alternation where both branches happen to repeat
			// the same strong literal `prefix`. The branches stay
			// filterable because each independently yields at least one
			// keyword; `prefix` shows up in both extracted slices because
			// the extractor walks each branch independently rather than
			// hoisting shared text out of an AST.
			name:    "top-level alternation with a repeated strong branch literal",
			pattern: `(?i)prefix.*api|prefix.*secret`,
			want:    []string{"prefix", "prefix", "secret"},
		},
		{
			// `*` is even more permissive than `?` (zero or more) and
			// must also trim the preceding character from the indexed
			// literal.
			name:    "trailing * makes preceding char optional",
			pattern: `abcds*\b`,
			want:    []string{"abcd"},
		},
		{
			// `{0,3}` is an optional quantifier (zero is allowed).
			name:    "trailing {0,n} makes preceding char optional",
			pattern: `abcds{0,3}\b`,
			want:    []string{"abcd"},
		},
		{
			// `{1,3}` requires at least one occurrence, so the preceding
			// character IS required.
			name:    "trailing {1,n} keeps preceding char",
			pattern: `abcds{1,3}\b`,
			want:    []string{"abcds"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractKeywords(tt.pattern)
			require.Equal(t, tt.want, got)
		})
	}
}

// TestPrefilterOverlappingKeywords is a regression test for a bug where the
// AC prefilter used FindAll (non-overlapping) and therefore silently dropped
// rule candidates when a shorter keyword was a prefix of a longer keyword
// at the same content position.
//
// Concrete case: "bash" and "bashrc" are both extracted as keywords, from
// different rules. When content contains "bashrc", "bash" matches first and
// FindAll suppresses the overlapping "bashrc" match, dropping every rule
// that was keyed only on "bashrc". EXTDL_005 was the observed victim.
//
// See: bashrc false-negative bug reported April 2026.
func TestPrefilterOverlappingKeywords(t *testing.T) {
	shortRule := &rules.CompiledRule{
		ID:        "SHORT",
		MatchMode: rules.MatchAny,
		Patterns: []rules.CompiledPattern{
			{Type: rules.PatternRegex, Value: "(?i)bash\\b", Regex: regexp.MustCompile(`(?i)bash\b`)},
		},
	}
	longRule := &rules.CompiledRule{
		ID:        "LONG",
		MatchMode: rules.MatchAny,
		Patterns: []rules.CompiledPattern{
			{Type: rules.PatternRegex, Value: "(?i)bashrc\\b", Regex: regexp.MustCompile(`(?i)bashrc\b`)},
		},
	}

	pf := buildPrefilter([]*rules.CompiledRule{shortRule, longRule})

	// Content containing only the longer literal must route to BOTH rules.
	// "bashrc" contains "bash" as a prefix substring, so a rule keyed on
	// "bash" is a legitimate candidate; the prefilter is a superset check,
	// the regex layer does the final filtering.
	got := pf.candidateRules("edit ~/.bashrc to persist")
	require.True(t, got["LONG"], "rule keyed on 'bashrc' must be a candidate when content has 'bashrc'")
	require.True(t, got["SHORT"], "rule keyed on 'bash' must be a candidate when content has 'bashrc' (bash is substring)")

	// Content with only the shorter literal must still route to SHORT.
	// LONG is correctly skipped because "bashrc" is not present.
	got = pf.candidateRules("run bash command")
	require.True(t, got["SHORT"], "rule keyed on 'bash' must be a candidate when content has 'bash'")
	require.False(t, got["LONG"], "rule keyed on 'bashrc' must NOT be a candidate when content has only 'bash'")
}

// TestPrefilterMatchModeAwareness pins how buildPrefilter resolves rules
// that contain at least one pattern with no extractable literal evidence.
// The match-mode semantics differ: under MatchAny a single unfilterable
// pattern means the rule must always run (any pattern matching is enough
// for a finding), while under MatchAll the other patterns' literals remain
// reliable because *every* pattern must match.
func TestPrefilterMatchModeAwareness(t *testing.T) {
	strongPat := rules.CompiledPattern{
		Type:  rules.PatternRegex,
		Value: "(?i)exfiltrate",
		Regex: regexp.MustCompile(`(?i)exfiltrate`),
	}
	// (a|b) has no >=4-char literal in any branch -> unfilterable.
	weakPat := rules.CompiledPattern{
		Type:  rules.PatternRegex,
		Value: "(?i)(a|b)",
		Regex: regexp.MustCompile(`(?i)(a|b)`),
	}

	anyRule := &rules.CompiledRule{
		ID:        "ANY_MIXED",
		MatchMode: rules.MatchAny,
		Patterns:  []rules.CompiledPattern{strongPat, weakPat},
	}
	allRule := &rules.CompiledRule{
		ID:        "ALL_MIXED",
		MatchMode: rules.MatchAll,
		Patterns:  []rules.CompiledPattern{strongPat, weakPat},
	}
	allWeakRule := &rules.CompiledRule{
		ID:        "ALL_WEAK",
		MatchMode: rules.MatchAll,
		Patterns:  []rules.CompiledPattern{weakPat, weakPat},
	}

	pf := buildPrefilter([]*rules.CompiledRule{anyRule, allRule, allWeakRule})

	// MatchAny + unfilterable pattern -> rule always runs.
	require.True(t, pf.noKeywordRules["ANY_MIXED"],
		"MatchAny rule with an unfilterable pattern must be noKeyword")

	// MatchAll + at least one filterable pattern -> rule is filtered on the
	// strong pattern's literal. Content lacking "exfiltrate" cannot match
	// pattern 1, so the rule cannot match either.
	require.False(t, pf.noKeywordRules["ALL_MIXED"],
		"MatchAll rule with a strong pattern must be filterable on it")
	got := pf.candidateRules("exfiltrate this data")
	require.True(t, got["ALL_MIXED"], "content with 'exfiltrate' must route ALL_MIXED")
	got = pf.candidateRules("totally unrelated text")
	require.False(t, got["ALL_MIXED"], "content without 'exfiltrate' must not route ALL_MIXED")

	// MatchAll + every pattern unfilterable -> rule must always run.
	require.True(t, pf.noKeywordRules["ALL_WEAK"],
		"MatchAll rule whose every pattern is unfilterable must be noKeyword")
}

func TestPrefilterTracksCandidatesPerPattern(t *testing.T) {
	strongPat := rules.CompiledPattern{
		Type:  rules.PatternRegex,
		Value: `(?i)exfiltrate`,
		Regex: regexp.MustCompile(`(?i)exfiltrate`),
	}
	weakPat := rules.CompiledPattern{
		Type:  rules.PatternRegex,
		Value: `\$(x|y)`,
		Regex: regexp.MustCompile(`\$(x|y)`),
	}
	rule := &rules.CompiledRule{
		ID:        "ANY_PATTERN_MASK",
		MatchMode: rules.MatchAny,
		Patterns:  []rules.CompiledPattern{strongPat, weakPat},
	}

	pf := buildPrefilter([]*rules.CompiledRule{rule})

	require.Equal(t, uint64(0b10), pf.candidatePatternMasks("ordinary text")[rule.ID],
		"the unfilterable pattern must always run while its filterable sibling stays skipped")
	require.Equal(t, uint64(0b11), pf.candidatePatternMasks("exfiltrate this data")[rule.ID],
		"the strong pattern must join the unconditional pattern when its required literal appears")
}

func TestPrefilterFallsBackAbovePatternMaskLimit(t *testing.T) {
	patterns := make([]rules.CompiledPattern, 65)
	for i := range patterns {
		patterns[i] = rules.CompiledPattern{
			Type:  rules.PatternRegex,
			Value: `distinctliteral`,
			Regex: regexp.MustCompile(`distinctliteral`),
		}
	}
	rule := &rules.CompiledRule{
		ID:        "CUSTOM_ABOVE_MASK_LIMIT",
		MatchMode: rules.MatchAny,
		Patterns:  patterns,
	}

	pf := buildPrefilter([]*rules.CompiledRule{rule})

	require.True(t, pf.unfiltered[rule.ID])
	require.True(t, pf.candidateRules("ordinary text")[rule.ID],
		"large custom rules must remain fully scanned instead of being truncated by the bitset fast path")
}

func TestPrefilterMatchesUnfilteredReference(t *testing.T) {
	rawRules, err := rules.LoadFromFS(builtin.FS())
	require.NoError(t, err)
	compiled, errs := rules.CompileAll(rawRules)
	require.Empty(t, errs)

	matcher := NewMatcher(compiled)
	byID := make(map[string]*rules.CompiledRule, len(compiled))
	for _, rule := range compiled {
		byID[rule.ID] = rule
	}

	for _, raw := range rawRules {
		rule := byID[raw.ID]
		if rule == nil {
			continue
		}
		filename := prefilterTestFilename(rule)
		examples := append(append([]string{}, raw.Examples.TruePositive...), raw.Examples.FalsePositive...)
		for exampleIndex, content := range examples {
			target := &scanner.Target{RelPath: filename, Content: []byte(content)}
			got, err := matcher.Analyze(context.Background(), target)
			require.NoError(t, err)
			want := analyzeWithoutKeywordPrefilter(matcher, target)
			require.Equalf(t, want, got, "rule=%s example=%d content=%q", raw.ID, exampleIndex, content)
		}
	}
}

func analyzeWithoutKeywordPrefilter(m *Matcher, target *scanner.Target) []scanner.Finding {
	content := target.StringContent()
	lowerContent := strings.ToLower(content)
	lines := target.Lines()
	var cbMap []bool
	if isMarkdown(target.RelPath) {
		cbMap = BuildCodeBlockMap(lines)
	}

	var findings []scanner.Finding
	for _, rule := range m.rulesForFile(target.RelPath) {
		switch rule.MatchMode {
		case rules.MatchAny:
			findings = append(findings,
				m.matchAnySelected(rule, ^uint64(0), content, lowerContent, lines, target, cbMap)...)
		case rules.MatchAll:
			findings = append(findings,
				m.matchAll(rule, content, lowerContent, lines, target, cbMap)...)
		}
	}
	findings = append(findings, DecodeAndRescan(target, m.allFileRules, cbMap)...)
	return findings
}

func prefilterTestFilename(rule *rules.CompiledRule) string {
	if len(rule.Targets) == 0 {
		return "selftest.txt"
	}
	target := rule.Targets[0]
	if strings.HasPrefix(target, "*.") {
		return "selftest" + target[1:]
	}
	return target
}

// TestPrefilterMCPCFG003Equivalent is a regression test for the specific
// shape that triggered the prefilter gap: a MatchAll rule whose first
// pattern has no >=4-char literal (env: { fragment) and whose second
// pattern has an alternation with one weak branch (API[_-]?KEY among the
// alternatives). Before the alternation-aware fix the rule was indexed on
// {secret, token, password, credential} and silently filtered out content
// like `{"env": {"API_KEY": "..."}}` because none of those four literals
// appeared. After the fix both patterns return zero literals and the rule
// must fall back to noKeyword so the scanner reaches the regex stage.
func TestPrefilterMCPCFG003Equivalent(t *testing.T) {
	envPat := rules.CompiledPattern{
		Type:  rules.PatternRegex,
		Value: `(?i)["']env["']\s*:\s*\{`,
		Regex: regexp.MustCompile(`(?i)["']env["']\s*:\s*\{`),
	}
	secretPat := rules.CompiledPattern{
		Type:  rules.PatternRegex,
		Value: `(?i)["'][A-Z_]*(API[_-]?KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)[A-Z_]*["']\s*:\s*["'][a-zA-Z0-9_\-]{20,}["']`,
		Regex: regexp.MustCompile(`(?i)["'][A-Z_]*(API[_-]?KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)[A-Z_]*["']\s*:\s*["'][a-zA-Z0-9_\-]{20,}["']`),
	}
	rule := &rules.CompiledRule{
		ID:        "MCPCFG_003",
		MatchMode: rules.MatchAll,
		Patterns:  []rules.CompiledPattern{envPat, secretPat},
	}

	pf := buildPrefilter([]*rules.CompiledRule{rule})

	require.True(t, pf.noKeywordRules["MCPCFG_003"],
		"MCPCFG_003-shaped rule must be noKeyword: both patterns are unfilterable")

	// Content with API_KEY but none of {secret, token, password, credential}
	// must still route to the rule. Before the fix this returned an empty
	// candidate set.
	got := pf.candidateRules(`{"env":{"github_api_key":"ghp_real1234567890abcdef"}}`)
	require.True(t, got["MCPCFG_003"],
		"content containing the MCPCFG_003 secret pattern must reach the rule")
}

func TestStripFlags(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"(?i)hello", "hello"},
		{"(?is)hello", "hello"},
		{"(?:hello)", "(?:hello)"},
		{"(?P<name>hello)", "(?P<name>hello)"},
		{"hello", "hello"},
		{"(?i)", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			require.Equal(t, tt.want, stripFlags(tt.input))
		})
	}
}
