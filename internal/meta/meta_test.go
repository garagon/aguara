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

func TestDedup_FullMode_CrossRuleCollapsed(t *testing.T) {
	findings := []types.Finding{
		{RuleID: "R1", FilePath: "a.md", Line: 5, Severity: types.SeverityHigh, Confidence: 0.9},
		{RuleID: "R2", FilePath: "a.md", Line: 5, Severity: types.SeverityMedium, Confidence: 0.8},
	}
	result := meta.DeduplicateWithMode(findings, types.DeduplicateFull)
	require.Len(t, result, 1, "cross-rule should be collapsed in Full mode")
	require.Equal(t, "R1", result[0].RuleID, "higher severity should win")
}

func TestDedup_SameRuleOnlyMode_CrossRulePreserved(t *testing.T) {
	findings := []types.Finding{
		{RuleID: "R1", FilePath: "a.md", Line: 5, Severity: types.SeverityHigh},
		{RuleID: "R2", FilePath: "a.md", Line: 5, Severity: types.SeverityMedium},
	}
	result := meta.DeduplicateWithMode(findings, types.DeduplicateSameRuleOnly)
	require.Len(t, result, 2, "cross-rule should be preserved in SameRuleOnly mode")
}

func TestDedup_SameRuleDupsAlwaysRemoved(t *testing.T) {
	findings := []types.Finding{
		{RuleID: "R1", FilePath: "a.md", Line: 5, Severity: types.SeverityHigh},
		{RuleID: "R1", FilePath: "a.md", Line: 5, Severity: types.SeverityMedium},
	}
	result := meta.DeduplicateWithMode(findings, types.DeduplicateSameRuleOnly)
	require.Len(t, result, 1, "same-rule dups should always be removed")
	require.Equal(t, types.SeverityHigh, result[0].Severity)
}

func TestDedup_DefaultIsFull(t *testing.T) {
	findings := []types.Finding{
		{RuleID: "R1", FilePath: "a.md", Line: 5, Severity: types.SeverityHigh},
		{RuleID: "R2", FilePath: "a.md", Line: 5, Severity: types.SeverityMedium},
	}
	result := meta.Deduplicate(findings)
	require.Len(t, result, 1, "default Deduplicate should use Full mode")
}

func TestComputeRiskScore_Empty(t *testing.T) {
	score := meta.ComputeRiskScore(nil)
	require.Equal(t, 0.0, score)
}

func TestComputeRiskScore_SingleCritical(t *testing.T) {
	findings := []types.Finding{
		{Score: 60},
	}
	score := meta.ComputeRiskScore(findings)
	require.InDelta(t, 60.0, score, 0.01)
}

func TestComputeRiskScore_MultipleMediums(t *testing.T) {
	findings := []types.Finding{
		{Score: 22.5},
		{Score: 22.5},
		{Score: 22.5},
	}
	// 22.5 * 1.0 + 22.5 * 0.5 + 22.5 * 0.25 = 22.5 + 11.25 + 5.625 = 39.375
	score := meta.ComputeRiskScore(findings)
	require.InDelta(t, 39.375, score, 0.01)
}

func TestComputeRiskScore_DiminishingReturns(t *testing.T) {
	findings := []types.Finding{
		{Score: 60},
		{Score: 37.5},
	}
	// 60 * 1.0 + 37.5 * 0.5 = 60 + 18.75 = 78.75
	score := meta.ComputeRiskScore(findings)
	require.InDelta(t, 78.75, score, 0.01)
}

func TestComputeRiskScore_Cap100(t *testing.T) {
	findings := []types.Finding{
		{Score: 100},
		{Score: 100},
		{Score: 100},
	}
	// 100 + 50 + 25 = 175 → capped at 100
	score := meta.ComputeRiskScore(findings)
	require.Equal(t, 100.0, score)
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
