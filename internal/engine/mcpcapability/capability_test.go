package mcpcapability

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/rules"
	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
	"github.com/stretchr/testify/require"
)

func TestCapabilityBoundaries(t *testing.T) {
	tests := []struct {
		name, path, content string
		want                bool
	}{
		{"issue291", "config.yaml", "securityContext:\n  capabilities: {drop: [ALL]}", false},
		{"block drop", "config.yaml", "capabilities:\n  drop: [ALL]\n  add: [NET_BIND_SERVICE]", false},
		{"drop after safe add", "config.yml", "capabilities: {add: [NET_RAW], drop: [ALL]}", false},
		{"drop before broad add", "config.yaml", "capabilities: {drop: [ALL], add: [ALL]}", true},
		{"block broad add", "config.yaml", "capabilities:\n  drop: [ALL]\n  add: [ALL]", true},
		{"block broad allow", "config.yaml", "permissions:\n  allow:\n    - read_files\n    - admin", true},
		{"sibling next line", "config.yaml", "capabilities: [read_files]\nallow: all", false},
		{"nested sibling", "config.yaml", "server:\n  capabilities: [read_files]\n  allow: all", false},
		{"JSON sibling", "config.json", `{"capabilities": ["read_files"], "allow": "all"}`, false},
		{"JSON outer sibling", "config.json", `{"server":{"capabilities":{"drop":["ALL"]}},"grant":"all"}`, false},
		{"quoted fake grant", "config.yaml", `capabilities: {drop: [ALL], note: "add: [ALL]"}`, false},
		{"list comment", "config.yaml", "capabilities: [read_files] # all", false},
		{"scalar comment", "config.yaml", "permissions: read_files # admin", false},
		{"commented grant", "config.yaml", "# capabilities: [ALL]", false},
		{"description value", "config.yaml", `permissions: "not admin"`, false},
		{"compound permission", "config.json", `{"permissions":"admin:read"}`, false},
		{"hyphenated permission", "config.yaml", "permissions: admin-read", false},
		{"prefix key", "config.yaml", "dropped_capabilities: [ALL]", false},
		{"suffix key", "config.yaml", "permissions_description: admin", false},
		{"empty value", "config.yaml", "capabilities:\nallow: all", false},
		{"empty flow object", "config.yaml", "{capabilities: {}, allow: all}", false},
		{"empty flow list", "config.yaml", "{capabilities: [], allow: all}", false},
		{"deny object", "config.yaml", "permissions: {deny: [admin]}", false},
		{"revoke object", "config.yaml", "permissions: {revoke: all}", false},
		{"nested deny", "config.yaml", "capabilities: {drop: {allow: all}}", false},
		{"nested declaration in drop", "config.yaml", "capabilities: {drop: {capabilities: all}}", false},
		{"boolean false", "config.yaml", "permissions: {admin: false}", false},
		{"boolean grant", "config.yaml", "permissions: {allow: true}", false},
		{"dangerous key", "config.yaml", "capabilities: {all: false}", false},
		{"list substring", "config.json", `{"capabilities":["read-all"]}`, false},
		{"multiline direct list", "config.yaml", "capabilities: [\n  read_files,\n  ALL\n]", true},
		{"nested server", "config.json", `{"servers":[{"capabilities":["all"]}]}`, true},
		{"nested data not grant", "config.yaml", "permissions: {allow: {description: admin}}", false},
		{"nested list not grant", "config.yaml", "capabilities: [[all]]", false},
		{"literal description", "config.yaml", "description: |\n  capabilities: [ALL]", false},
		{"folded description", "config.yaml", "description: >\n  permissions: admin", false},
		{"JSON string", "config.json", `{"description":"capabilities: [ALL]"}`, false},
		{"escaped JSON string", "config.json", `{"description":"see \"capabilities\": [\"all\"]"}`, false},
		{"JSON unicode", "config.json", `{"permissions":"\u0061dmin"}`, true},
		{"root scalar", "config.yaml", `"capabilities: [ALL]"`, false},
		{"duplicate field", "config.yaml", "capabilities: [ALL]\ncapabilities: [read_files]", false},
		{"duplicate grant", "config.yaml", "permissions: {allow: admin, allow: read_files}", false},
		{"alias not expanded", "config.yaml", "broad: &b [ALL]\ncapabilities: *b", false},
		{"merge not expanded", "config.yaml", "base: &b {allow: all}\npermissions: {<<: *b}", false},
		{"alias cycle", "config.yaml", "capabilities: &x [*x]", false},
		{"alias next to grant", "config.yaml", "base: &b [all]\ncapabilities: {drop: *b, add: [all]}", true},
		{"malformed", "config.yaml", "capabilities: [ALL", false},
		{"JSON must be JSON", "config.json", "{capabilities: all}", false},
		{"unterminated quote", "config.yaml", "permissions: \"admin", false},
		{"multiple docs", "config.yaml", "capabilities: {drop: [ALL]}\n---\npermissions: [admin]", true},
		{"prose request", "skill.txt", "request unrestricted capabilities", true},
		{"wrapped prose request", "skill.txt", "request unrestricted\ncapabilities", true},
		{"prose benign", "skill.md", "The tool has limited access permissions", false},
		{"prose request in JSON data", "config.json", `{"description":"request unrestricted capabilities"}`, false},
		{"standalone snippet", "skill.md", `"capabilities": ["all"]`, true},
		{"assignment snippet", "skill.txt", "permissions = admin", true},
		{"non-config script", "script.js", `const config = {capabilities: ["all"]}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := New().Analyze(context.Background(), &scanner.Target{RelPath: tt.path, Content: []byte(tt.content)})
			require.NoError(t, err)
			require.Equal(t, tt.want, len(findings) > 0, "input: %s", tt.content)
			for _, finding := range findings {
				require.Equal(t, RuleCapabilityEscalation, finding.RuleID)
				require.Equal(t, types.SeverityHigh, finding.Severity)
				require.Equal(t, "mcp-attack", finding.Category)
				require.Positive(t, finding.Line)
			}
		})
	}
}

func TestGrantTokenMatrix(t *testing.T) {
	check := func(t *testing.T, content string, want bool) {
		t.Helper()
		findings, err := New().Analyze(context.Background(), &scanner.Target{RelPath: "config.yaml", Content: []byte(content)})
		require.NoError(t, err)
		require.Equal(t, want, len(findings) > 0, "input: %s", content)
	}
	for _, field := range []string{"capabilities", "permissions"} {
		for _, token := range []string{"all", "admin", "unrestricted", "root", "superuser", "full_access", "god_mode"} {
			for _, quote := range []string{"", `"`, "'"} {
				key, value := quote+field+quote, quote+strings.ToUpper(token)+quote
				t.Run(field+"/"+token+"/"+quote, func(t *testing.T) {
					check(t, key+": "+value, true)
					check(t, key+": [read_files, "+value+", search]", true)
					for _, grant := range []string{"add", "allow", "grant"} {
						check(t, fmt.Sprintf("%s: {%s%s%s: [%s]}", key, quote, grant, quote, value), true)
						check(t, fmt.Sprintf("%s:\n  %s:\n    - %s", key, grant, value), true)
						check(t, fmt.Sprintf("%s: {drop: [%s], %s: read_files}", key, value, grant), false)
						check(t, fmt.Sprintf("%s: [read_files]\n%s: %s", key, grant, value), false)
					}
					for _, denied := range []string{"drop", "deny", "revoke", "remove"} {
						check(t, fmt.Sprintf("%s: {%s: [%s]}", key, denied, value), false)
					}
				})
			}
		}
	}
}

func TestCapabilityEvidenceAndLimits(t *testing.T) {
	t.Run("prose retains normalized text detection", func(t *testing.T) {
		findings, err := New().Analyze(context.Background(), &scanner.Target{
			RelPath:         "skill.txt",
			Content:         []byte("request unrestricted capabilities"),
			OriginalContent: []byte("ｒｅｑｕｅｓｔ unrestricted capabilities"),
		})
		require.NoError(t, err)
		require.Len(t, findings, 1)
	})
	t.Run("wrapped prose preserves subsequent line numbers", func(t *testing.T) {
		findings, err := New().Analyze(context.Background(), &scanner.Target{
			RelPath: "skill.txt",
			Content: []byte("# Title\nrequest unrestricted\ncapabilities\n\nrequest admin access"),
		})
		require.NoError(t, err)
		require.Len(t, findings, 2)
		require.Equal(t, 2, findings[0].Line)
		require.Equal(t, 5, findings[1].Line)
	})
	t.Run("low override is not downgraded to info", func(t *testing.T) {
		analyzer := NewWithOverride(rules.RuleOverride{Severity: "LOW"})
		findings, err := analyzer.Analyze(context.Background(), &scanner.Target{
			RelPath: "skill.md", Content: []byte("```yaml\npermissions: admin\n```"),
		})
		require.NoError(t, err)
		require.Len(t, findings, 1)
		require.Equal(t, types.SeverityLow, findings[0].Severity)
	})
	t.Run("fenced snippets preserve locations and downgrade", func(t *testing.T) {
		content := "# Example\n\n```yaml\ncapabilities:\n  add: [ALL]\n```\n"
		findings, err := New().Analyze(context.Background(), &scanner.Target{RelPath: "skill.md", Content: []byte(content)})
		require.NoError(t, err)
		require.Len(t, findings, 1)
		require.Equal(t, 5, findings[0].Line)
		require.Equal(t, types.SeverityMedium, findings[0].Severity)
		require.True(t, findings[0].InCodeBlock)
	})
	t.Run("evidence excludes unrelated secrets", func(t *testing.T) {
		content := `{"capabilities":["all"],"token":"unrelated-secret"}`
		findings, err := New().Analyze(context.Background(), &scanner.Target{RelPath: "config.json", Content: []byte(content)})
		require.NoError(t, err)
		require.Len(t, findings, 1)
		require.NotContains(t, findings[0].MatchedText, "unrelated-secret")
		require.Empty(t, findings[0].Context)
	})
	t.Run("cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := New().Analyze(ctx, &scanner.Target{RelPath: "config.yaml", Content: []byte("capabilities: all")})
		require.ErrorIs(t, err, context.Canceled)
	})
	t.Run("disabled override skips parsing and budgets", func(t *testing.T) {
		content := "capabilities: all\n" + strings.Repeat(" ", maxConfigBytes)
		findings, err := NewWithOverride(rules.RuleOverride{Disabled: true}).Analyze(
			context.Background(), &scanner.Target{RelPath: "config.yaml", Content: []byte(content)},
		)
		require.NoError(t, err)
		require.Empty(t, findings)
	})
	t.Run("size limit is an error not a clean scan", func(t *testing.T) {
		content := "capabilities: all\n" + strings.Repeat(" ", maxConfigBytes)
		_, err := New().Analyze(context.Background(), &scanner.Target{RelPath: "config.yaml", Content: []byte(content)})
		require.ErrorContains(t, err, "input limit")
	})
}
