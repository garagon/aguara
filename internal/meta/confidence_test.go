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
	require.InDelta(t, 0.459, result[0].Confidence, 0.01) // 0.85 * 0.6 (code block) * 0.9 (md)
	require.InDelta(t, 0.765, result[1].Confidence, 0.01) // 0.85 * 0.9 (md)
}

func TestAdjustConfidenceCorrelationBoost(t *testing.T) {
	findings := []types.Finding{
		{RuleID: "R1", FilePath: "a.md", Line: 5, Confidence: 0.85},
		{RuleID: "R2", FilePath: "a.md", Line: 7, Confidence: 0.85}, // within 5 lines
		{RuleID: "R3", FilePath: "a.md", Line: 50, Confidence: 0.85}, // far away, no boost
	}

	result := meta.AdjustConfidence(findings)
	require.InDelta(t, 0.8415, result[0].Confidence, 0.01) // 0.85 * 0.9 (md) * 1.1 (correlated)
	require.InDelta(t, 0.8415, result[1].Confidence, 0.01) // 0.85 * 0.9 (md) * 1.1 (correlated)
	require.InDelta(t, 0.765, result[2].Confidence, 0.01)  // 0.85 * 0.9 (md), no boost
}

func TestAdjustConfidenceCapAtOne(t *testing.T) {
	// Use .py to avoid md multiplier and isolate the cap behavior
	findings := []types.Finding{
		{RuleID: "R1", FilePath: "a.py", Line: 5, Confidence: 0.95},
		{RuleID: "R2", FilePath: "a.py", Line: 7, Confidence: 0.95},
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
	// R1: 0.85 * 0.6 (code block) * 0.9 (md) * 1.1 (correlated) = 0.5049
	require.InDelta(t, 0.5049, result[0].Confidence, 0.01)
	// R2: 0.85 * 0.9 (md) * 1.1 (correlated) = 0.8415
	require.InDelta(t, 0.8415, result[1].Confidence, 0.01)
}

func TestAdjustConfidenceNegativeClampedToZero(t *testing.T) {
	findings := []types.Finding{
		{RuleID: "R1", FilePath: "a.md", Line: 5, Confidence: -0.5},
	}

	result := meta.AdjustConfidence(findings)
	require.Equal(t, float64(0), result[0].Confidence)
}

func TestAdjustConfidenceDocSectionDowngrade(t *testing.T) {
	findings := []types.Finding{
		{
			RuleID: "R1", FilePath: "README.md", Line: 5, Confidence: 0.85,
			Context: []types.ContextLine{
				{Line: 3, Content: "## Installation"},
				{Line: 4, Content: ""},
				{Line: 5, Content: "pip install evil-package", IsMatch: true},
			},
		},
		{
			RuleID: "R2", FilePath: "skill.md", Line: 10, Confidence: 0.85,
			Context: []types.ContextLine{
				{Line: 9, Content: "Some normal text"},
				{Line: 10, Content: "pip install evil-package", IsMatch: true},
			},
		},
	}

	result := meta.AdjustConfidence(findings)
	// R1 near "## Installation": 0.85 * 0.7 (doc section) * 0.9 (md file) = 0.5355
	require.InDelta(t, 0.5355, result[0].Confidence, 0.01)
	// R2 not in doc section: 0.85 * 0.9 (md file) = 0.765
	require.InDelta(t, 0.765, result[1].Confidence, 0.01)
}

func TestAdjustConfidenceFileTypeMultiplier(t *testing.T) {
	findings := []types.Finding{
		{RuleID: "R1", FilePath: "skill.md", Line: 5, Confidence: 0.85},
		{RuleID: "R2", FilePath: "helper.py", Line: 5, Confidence: 0.85},
		{RuleID: "R3", FilePath: "config.yaml", Line: 5, Confidence: 0.85},
	}

	result := meta.AdjustConfidence(findings)
	require.InDelta(t, 0.765, result[0].Confidence, 0.01) // .md: 0.85 * 0.9
	require.InDelta(t, 0.85, result[1].Confidence, 0.01)   // .py: no change
	require.InDelta(t, 0.85, result[2].Confidence, 0.01)   // .yaml: no change
}

func TestAdjustConfidenceZeroConfidenceUntouched(t *testing.T) {
	findings := []types.Finding{
		{RuleID: "R1", FilePath: "a.md", Line: 5, Confidence: 0, InCodeBlock: true},
	}

	result := meta.AdjustConfidence(findings)
	require.Equal(t, float64(0), result[0].Confidence)
}
