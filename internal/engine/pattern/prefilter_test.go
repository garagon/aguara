package pattern

import (
	"regexp"
	"testing"

	"github.com/garagon/aguara/internal/rules"
	"github.com/stretchr/testify/require"
)

func TestExtractKeywords(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		want    []string
	}{
		{
			name:    "simple literal with flag",
			pattern: `(?i)subprocess\.(run|call|Popen)`,
			want:    []string{"subprocess", "call", "popen"},
		},
		{
			name:    "escaped metachar",
			pattern: `(?i)\beval\s*\(`,
			want:    []string{"eval"},
		},
		{
			name:    "alternation with short branches",
			pattern: `(?i)(curl|wget)\s+[^|]+\|\s*(bash|sh)\b`,
			want:    []string{"curl", "wget", "bash"},
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
			name:    "private key header",
			pattern: `-----BEGIN\s+(RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE KEY`,
			want:    []string{"begin", "openssh", "private"},
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
			name:    "mixed length alternation",
			pattern: `(?i)(password|passwd|pwd)\s*[=:]`,
			want:    []string{"password", "passwd"},
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
