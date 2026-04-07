package pattern

import (
	"testing"

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
