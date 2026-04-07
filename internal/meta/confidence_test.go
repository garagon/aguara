package meta_test

import (
	"testing"

	"github.com/garagon/aguara/internal/meta"
	"github.com/garagon/aguara/internal/types"
	"github.com/stretchr/testify/require"
)

func TestAdjustConfidenceCodeBlockDowngrade(t *testing.T) {
	findings := []types.Finding{
		{RuleID: "R1", FilePath: "a.md", Line: 5, Confidence: 0.85, InCodeBlock: true},
		{RuleID: "R2", FilePath: "a.md", Line: 20, Confidence: 0.85, InCodeBlock: false},
	}

	result := meta.AdjustConfidence(findings)
	require.InDelta(t, 0.51, result[0].Confidence, 0.01) // 0.85 * 0.6
	require.InDelta(t, 0.85, result[1].Confidence, 0.01) // unchanged
}

func TestAdjustConfidenceCorrelationBoost(t *testing.T) {
	findings := []types.Finding{
		{RuleID: "R1", FilePath: "a.md", Line: 5, Confidence: 0.85},
		{RuleID: "R2", FilePath: "a.md", Line: 7, Confidence: 0.85}, // within 5 lines
		{RuleID: "R3", FilePath: "a.md", Line: 50, Confidence: 0.85}, // far away, no boost
	}

	result := meta.AdjustConfidence(findings)
	require.InDelta(t, 0.935, result[0].Confidence, 0.01) // 0.85 * 1.1
	require.InDelta(t, 0.935, result[1].Confidence, 0.01) // 0.85 * 1.1
	require.InDelta(t, 0.85, result[2].Confidence, 0.01)  // no boost
}

func TestAdjustConfidenceCapAtOne(t *testing.T) {
	findings := []types.Finding{
		{RuleID: "R1", FilePath: "a.md", Line: 5, Confidence: 0.95},
		{RuleID: "R2", FilePath: "a.md", Line: 7, Confidence: 0.95},
	}

	result := meta.AdjustConfidence(findings)
	// 0.95 * 1.1 = 1.045, capped at 1.0
	require.Equal(t, 1.0, result[0].Confidence)
	require.Equal(t, 1.0, result[1].Confidence)
}

func TestAdjustConfidenceCodeBlockAndCorrelation(t *testing.T) {
	findings := []types.Finding{
		{RuleID: "R1", FilePath: "a.md", Line: 5, Confidence: 0.85, InCodeBlock: true},
		{RuleID: "R2", FilePath: "a.md", Line: 7, Confidence: 0.85, InCodeBlock: false},
	}

	result := meta.AdjustConfidence(findings)
	// R1: 0.85 * 0.6 (code block) = 0.51, then * 1.1 (correlated) = 0.561
	require.InDelta(t, 0.561, result[0].Confidence, 0.01)
	// R2: 0.85 * 1.1 (correlated) = 0.935
	require.InDelta(t, 0.935, result[1].Confidence, 0.01)
}

func TestAdjustConfidenceNegativeClampedToZero(t *testing.T) {
	findings := []types.Finding{
		{RuleID: "R1", FilePath: "a.md", Line: 5, Confidence: -0.5},
	}

	result := meta.AdjustConfidence(findings)
	require.Equal(t, float64(0), result[0].Confidence)
}

func TestAdjustConfidenceZeroConfidenceUntouched(t *testing.T) {
	findings := []types.Finding{
		{RuleID: "R1", FilePath: "a.md", Line: 5, Confidence: 0, InCodeBlock: true},
	}

	result := meta.AdjustConfidence(findings)
	require.Equal(t, float64(0), result[0].Confidence)
}
