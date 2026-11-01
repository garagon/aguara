package aguara_test

import (
	"context"
	"testing"

	"github.com/garagon/aguara"
	"github.com/stretchr/testify/require"
)

func TestMCP009PublicContract(t *testing.T) {
	sc, err := aguara.NewScanner()
	require.NoError(t, err)
	for _, tt := range []struct {
		content string
		want    bool
	}{
		{"securityContext:\n  capabilities: {drop: [ALL]}", false},
		{"server:\n  capabilities: [read_files]\n  allow: all", false},
		{"capabilities:\n  drop: [ALL]\n  add: [ALL]", true},
		{`{"capabilities":["all"]}`, true},
		{`{"capabilities":["ａｌｌ"]}`, false},
		{`{"ｃａｐａｂｉｌｉｔｉｅｓ":["all"]}`, false},
	} {
		result, err := sc.ScanContent(context.Background(), tt.content, "config.yaml")
		require.NoError(t, err)
		var found bool
		for _, f := range result.Findings {
			if f.RuleID == "MCP_009" {
				found = true
				require.Equal(t, aguara.SeverityHigh, f.Severity)
				require.Equal(t, "mcp-capability", f.Analyzer)
			}
		}
		require.Equal(t, tt.want, found, "input: %s", tt.content)
	}
	detail, err := sc.ExplainRule("MCP_009")
	require.NoError(t, err)
	require.Equal(t, "HIGH", detail.Severity)
	require.Equal(t, "mcp-attack", detail.Category)
	require.Equal(t, "mcp-capability", detail.Analyzer)
	count := 0
	for _, r := range sc.ListRules() {
		if r.ID == "MCP_009" {
			count++
		}
	}
	require.Equal(t, 1, count)

	disabled, err := aguara.NewScanner(aguara.WithDisabledRules("MCP_009"))
	require.NoError(t, err)
	result, err := disabled.ScanContent(context.Background(), "capabilities: all", "config.yaml")
	require.NoError(t, err)
	for _, f := range result.Findings {
		require.NotEqual(t, "MCP_009", f.RuleID)
	}
	for _, disabled := range []bool{false, true} {
		opts := aguara.WithRuleOverrides(map[string]aguara.RuleOverride{
			"MCP_009": {Severity: "LOW", Disabled: disabled},
		})
		custom, err := aguara.NewScanner(opts)
		require.NoError(t, err)
		result, err := custom.ScanContent(context.Background(), "permissions: admin", "config.yaml")
		require.NoError(t, err)
		count := 0
		for _, f := range result.Findings {
			if f.RuleID == "MCP_009" {
				count++
				require.Equal(t, aguara.SeverityLow, f.Severity)
			}
		}
		if disabled {
			require.Zero(t, count)
			_, err := custom.ExplainRule("MCP_009")
			require.Error(t, err)
		} else {
			require.Equal(t, 1, count)
			detail, err := custom.ExplainRule("MCP_009")
			require.NoError(t, err)
			require.Equal(t, "LOW", detail.Severity)
		}
	}
}
