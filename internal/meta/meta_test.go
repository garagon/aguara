package meta_test

import (
	"testing"

	"github.com/garagon/aguara/internal/meta"
	"github.com/garagon/aguara/internal/types"
	"github.com/stretchr/testify/require"
)

func TestDeduplicate(t *testing.T) {
	findings := []types.Finding{
		{RuleID: "R1", FilePath: "a.md", Line: 5, Severity: types.SeverityHigh},
		{RuleID: "R1", FilePath: "a.md", Line: 5, Severity: types.SeverityCritical}, // dup, higher sev
		{RuleID: "R2", FilePath: "a.md", Line: 10, Severity: types.SeverityLow},
	}

	result := meta.Deduplicate(findings)
	require.Len(t, result, 2)

	// Find the R1 finding — should have CRITICAL severity
	for _, f := range result {
		if f.RuleID == "R1" {
			require.Equal(t, types.SeverityCritical, f.Severity)
		}
	}
}

func TestScoreFindings(t *testing.T) {
	findings := []types.Finding{
		{Severity: types.SeverityCritical, Category: "prompt-injection"},
		{Severity: types.SeverityHigh, Category: "exfiltration"},
		{Severity: types.SeverityLow, Category: "unknown-category"},
	}

	scored := meta.ScoreFindings(findings)
	require.Equal(t, float64(60), scored[0].Score) // 40 * 1.5
	require.Equal(t, float64(35), scored[1].Score) // 25 * 1.4
	require.Equal(t, float64(8), scored[2].Score)  // 8 * 1.0
}

func TestCorrelate(t *testing.T) {
	findings := []types.Finding{
		{FilePath: "a.md", Line: 5, Score: 10},
		{FilePath: "a.md", Line: 7, Score: 20},  // within 5 lines
		{FilePath: "a.md", Line: 50, Score: 30}, // far away
		{FilePath: "b.md", Line: 1, Score: 15},
	}

	groups := meta.Correlate(findings)
	require.GreaterOrEqual(t, len(groups), 3)

	// Find the group with 2 findings (lines 5 and 7)
	for _, g := range groups {
		if len(g.Findings) == 2 {
			// Should have correlation bonus
			for _, f := range g.Findings {
				require.Greater(t, f.Score, float64(0))
			}
			return
		}
	}
	t.Fatal("expected a group with 2 correlated findings")
}
