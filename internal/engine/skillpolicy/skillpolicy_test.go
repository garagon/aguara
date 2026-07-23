package skillpolicy

import (
	"context"
	"testing"

	"github.com/garagon/aguara/internal/scanner"
	"github.com/stretchr/testify/require"
)

func analyze(t *testing.T, path, content string) []scanner.Finding {
	t.Helper()
	findings, err := New().Analyze(context.Background(), &scanner.Target{
		Path:    path,
		RelPath: path,
		Content: []byte(content),
	})
	require.NoError(t, err)
	return findings
}

func TestWildcardTools(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		content string
		want    bool
		line    int
	}{
		{
			name:    "single quoted wildcard",
			path:    "SKILL.md",
			content: "---\nname: demo\nallowed-tools: '*'\n---\n# Demo\n",
			want:    true,
			line:    3,
		},
		{
			name:    "double quoted wildcard",
			path:    "skills/demo/SKILL.md",
			content: "---\nname: demo\nallowed-tools: \"*\"\n---\n",
			want:    true,
			line:    3,
		},
		{
			name:    "sequence is not a valid allowed tools string",
			path:    "skill.md",
			content: "---\nallowed-tools:\n  - Read\n  - \"*\"\n---\n",
		},
		{
			name:    "utf8 bom",
			path:    "SKILL.md",
			content: "\ufeff---\nallowed-tools: '*'\n---\n",
			want:    true,
			line:    2,
		},
		{
			name:    "explicit tools",
			path:    "SKILL.md",
			content: "---\nallowed-tools: Read, Grep, Glob\n---\n",
		},
		{
			name:    "scoped command wildcard",
			path:    "SKILL.md",
			content: "---\nallowed-tools: Bash(gh:*)\n---\n",
		},
		{
			name:    "wildcard in body",
			path:    "SKILL.md",
			content: "---\nname: demo\n---\nExample: allowed-tools: '*'\n",
		},
		{
			name:    "wildcard in fenced example",
			path:    "SKILL.md",
			content: "---\nname: demo\n---\n```yaml\nallowed-tools: '*'\n```\n",
		},
		{
			name:    "nested metadata key",
			path:    "SKILL.md",
			content: "---\nmetadata:\n  allowed-tools: '*'\n---\n",
		},
		{
			name:    "wrong key spelling",
			path:    "SKILL.md",
			content: "---\nallowedTools: '*'\nallowed_tools: '*'\nAllowed-Tools: '*'\n---\n",
		},
		{
			name:    "unquoted alias token is invalid yaml",
			path:    "SKILL.md",
			content: "---\nallowed-tools: *\n---\n",
		},
		{
			name:    "malformed frontmatter",
			path:    "SKILL.md",
			content: "---\nallowed-tools: [\"*\"\n---\n",
		},
		{
			name:    "missing closing delimiter",
			path:    "SKILL.md",
			content: "---\nallowed-tools: '*'\n",
		},
		{
			name:    "not a skill file",
			path:    "README.md",
			content: "---\nallowed-tools: '*'\n---\n",
		},
		{
			name:    "later explicit duplicate wins",
			path:    "SKILL.md",
			content: "---\nallowed-tools: '*'\nallowed-tools: Read, Grep\n---\n",
		},
		{
			name:    "later wildcard duplicate wins",
			path:    "SKILL.md",
			content: "---\nallowed-tools: Read, Grep\nallowed-tools: '*'\n---\n",
			want:    true,
			line:    3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := analyze(t, tt.path, tt.content)
			if !tt.want {
				require.Empty(t, findings)
				return
			}
			require.Len(t, findings, 1)
			require.Equal(t, RuleWildcardTools, findings[0].RuleID)
			require.Equal(t, tt.line, findings[0].Line)
			require.Equal(t, AnalyzerName, findings[0].Analyzer)
		})
	}
}
