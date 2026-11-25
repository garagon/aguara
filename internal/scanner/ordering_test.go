package scanner_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
	"github.com/stretchr/testify/require"
)

// TestScannerFindingOrderIsTotal runs a scan whose findings tie on severity,
// file and line (several rules on one line, kept by same-rule-only dedup).
// The final sort used to compare only severity, file and line with an
// unstable sort, so ties came out in map-iteration order.
func TestScannerFindingOrderIsTotal(t *testing.T) {
	analyzer := &mockAnalyzer{name: "mock", findings: []types.Finding{
		{RuleID: "RULE_C", Severity: types.SeverityHigh, Line: 3, Column: 1, MatchedText: "c"},
		{RuleID: "RULE_A", Severity: types.SeverityHigh, Line: 3, Column: 1, MatchedText: "a"},
		{RuleID: "RULE_B", Severity: types.SeverityHigh, Line: 3, Column: 1, MatchedText: "b"},
		{RuleID: "RULE_D", Severity: types.SeverityHigh, Line: 3, Column: 7, MatchedText: "d"},
		{RuleID: "RULE_E", Severity: types.SeverityHigh, Line: 1, Column: 9, MatchedText: "e"},
		{RuleID: "RULE_F", Severity: types.SeverityCritical, Line: 9, Column: 1, MatchedText: "f"},
	}}

	scan := func() []string {
		s := scanner.New(4)
		s.SetDeduplicateMode(types.DeduplicateSameRuleOnly)
		s.RegisterAnalyzer(analyzer)
		var targets []*scanner.Target
		for i := 0; i < 8; i++ {
			targets = append(targets, &scanner.Target{RelPath: fmt.Sprintf("dir/file%d.md", i), Content: []byte("x\ny\nz\n")})
		}
		result, err := s.ScanTargets(context.Background(), targets)
		require.NoError(t, err)
		out := make([]string, 0, len(result.Findings))
		for _, f := range result.Findings {
			out = append(out, fmt.Sprintf("%s:%s:%d:%d:%s", f.Severity, f.FilePath, f.Line, f.Column, f.RuleID))
		}
		return out
	}

	first := scan()
	require.Len(t, first, 48)
	// Severity first, then path, line, column and rule ID.
	require.Equal(t, []string{
		"CRITICAL:dir/file0.md:9:1:RULE_F",
		"CRITICAL:dir/file1.md:9:1:RULE_F",
	}, first[:2])
	require.Equal(t, []string{
		"HIGH:dir/file0.md:1:9:RULE_E",
		"HIGH:dir/file0.md:3:1:RULE_A",
		"HIGH:dir/file0.md:3:1:RULE_B",
		"HIGH:dir/file0.md:3:1:RULE_C",
		"HIGH:dir/file0.md:3:7:RULE_D",
	}, first[8:13])
	for run := 0; run < 50; run++ {
		require.Equal(t, first, scan(), "run %d produced a different order", run)
	}
}
