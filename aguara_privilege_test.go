package aguara_test

import (
	"context"
	"testing"

	"github.com/garagon/aguara"
	"github.com/stretchr/testify/require"
)

func TestSUPPLY007PublicContract(t *testing.T) {
	sc, err := aguara.NewScanner()
	require.NoError(t, err)
	for _, content := range []string{
		"capabilities: {drop: [SETUID, SETGID]}",
		"# Drop SETUID and SETGID\ncapabilities: {drop: [ALL]}",
		`{"description":"This policy drops SETUID and SETGID.","setuid":false}`,
	} {
		result, err := sc.ScanContent(context.Background(), content, "config.yaml")
		require.NoError(t, err)
		for _, f := range result.Findings {
			require.NotEqual(t, "SUPPLY_007", f.RuleID, "%+v", f)
		}
	}
	const content = "# SETUID is removed below\ncapabilities:\n  drop: [SETUID]\n  add: [SETGID]\n"
	result, err := sc.ScanContent(context.Background(), content, "config.yaml")
	require.NoError(t, err)
	count := 0
	for _, f := range result.Findings {
		if f.RuleID == "SUPPLY_007" {
			count++
			require.Equal(t, 4, f.Line)
			require.Equal(t, "SETGID", f.MatchedText)
			require.Equal(t, aguara.SeverityHigh, f.Severity)
			require.Equal(t, "pattern", f.Analyzer)
		}
	}
	require.Equal(t, 1, count)
	detail, err := sc.ExplainRule("SUPPLY_007")
	require.NoError(t, err)
	require.Equal(t, "HIGH", detail.Severity)
	require.Equal(t, "supply-chain", detail.Category)
	require.Empty(t, detail.Analyzer, "YAML catalog metadata retains its existing representation")
	for _, disabled := range []bool{false, true} {
		custom, err := aguara.NewScanner(aguara.WithRuleOverrides(map[string]aguara.RuleOverride{
			"SUPPLY_007": {Severity: "LOW", Disabled: disabled},
		}))
		require.NoError(t, err)
		result, err := custom.ScanContent(context.Background(), content, "config.yaml")
		require.NoError(t, err)
		count = 0
		for _, f := range result.Findings {
			if f.RuleID == "SUPPLY_007" {
				count++
				require.Equal(t, aguara.SeverityLow, f.Severity)
			}
		}
		if disabled {
			require.Zero(t, count)
		} else {
			require.Equal(t, 1, count)
		}
	}
}
