package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateManifestRejectsUnsafeAndDuplicateCases(t *testing.T) {
	base := manifest{
		SchemaVersion: 1,
		Name:          "bench",
		License:       "Apache-2.0",
		Cases: []benchCase{{
			ID: "one", Surface: "agent", Command: "scan",
			Files: map[string]string{"skill.md": "safe"},
		}},
	}
	require.NoError(t, validateManifest(base))

	dup := base
	dup.Cases = append(dup.Cases, dup.Cases[0])
	require.ErrorContains(t, validateManifest(dup), "duplicate case id")

	unsafe := base
	unsafe.Cases = append([]benchCase(nil), base.Cases...)
	unsafe.Cases[0].Files = map[string]string{"../escape": "bad"}
	require.ErrorContains(t, validateManifest(unsafe), "unsafe file path")

	unsafeID := base
	unsafeID.Cases = append([]benchCase(nil), base.Cases...)
	unsafeID.Cases[0].ID = "../escape"
	require.ErrorContains(t, validateManifest(unsafeID), "lowercase slugs")

	duplicateExpectation := base
	duplicateExpectation.Cases = append([]benchCase(nil), base.Cases...)
	duplicateExpectation.Cases[0].Expected = []expectation{
		{Kind: "rule_id", Value: "RULE_001"},
		{Kind: "rule_id", Value: "RULE_001"},
	}
	require.ErrorContains(t, validateManifest(duplicateExpectation), "duplicate expected entry")
}

func TestCollectObservationsAndCompare(t *testing.T) {
	doc := map[string]any{
		"findings": []any{
			map[string]any{"rule_id": "RULE_001", "severity": float64(3)},
			map[string]any{"rule_id": "RULE_001", "severity": float64(3)},
			map[string]any{"title": "Known malicious package: bad@1.0.0", "severity": "CRITICAL"},
		},
	}
	observed := collectObservations(doc)
	require.Equal(t, []observation{
		{Kind: "rule_id", Value: "RULE_001"},
		{Kind: "title", Value: "Known malicious package: bad@1.0.0"},
	}, observed)

	missing, unexpected := compare([]expectation{
		{Kind: "rule_id", Value: "RULE_001"},
		{Kind: "title_contains", Value: "bad@1.0.0"},
	}, observed)
	require.Empty(t, missing)
	require.Empty(t, unexpected)
}

func TestCalculateMetricsUsesCaseLevelFPR(t *testing.T) {
	cases := []caseResult{
		{ID: "tp", Expected: []expectation{{Kind: "rule_id", Value: "R"}}},
		{ID: "fn", Expected: []expectation{{Kind: "rule_id", Value: "M"}}, Missing: []expectation{{Kind: "rule_id", Value: "M"}}},
		{ID: "clean"},
		{ID: "fp", Unexpected: []observation{{Kind: "rule_id", Value: "X"}}},
	}
	m := calculateMetrics(cases)
	require.Equal(t, 1, m.TruePositives)
	require.Equal(t, 1, m.FalsePositives)
	require.Equal(t, 1, m.FalseNegatives)
	require.InDelta(t, 0.5, m.Precision, 0.0001)
	require.InDelta(t, 0.5, m.Recall, 0.0001)
	require.InDelta(t, 0.5, m.BenignCaseFPR, 0.0001)
}

func TestPartitionKnownUnexpectedPreservesHonestMetrics(t *testing.T) {
	observed := []observation{
		{Kind: "rule_id", Value: "KNOWN_FP"},
		{Kind: "rule_id", Value: "NEW_FP"},
	}
	known, unacknowledged, stale := partitionKnownUnexpected([]expectation{
		{Kind: "rule_id", Value: "KNOWN_FP"},
		{Kind: "rule_id", Value: "FIXED_FP"},
	}, observed)
	require.Equal(t, observed[:1], known)
	require.Equal(t, observed[1:], unacknowledged)
	require.Equal(t, []expectation{{Kind: "rule_id", Value: "FIXED_FP"}}, stale)
}

func TestIsolatedEnvReplacesTrustRelevantVariables(t *testing.T) {
	t.Setenv("HOME", "/leaky-home")
	t.Setenv("XDG_CONFIG_HOME", "/leaky-config")
	t.Setenv("AGUARA_INSECURE_INTEL", "1")
	env := isolatedEnv("/isolated")
	joined := "\n" + strings.Join(env, "\n") + "\n"
	require.Contains(t, joined, "\nHOME=/isolated\n")
	require.Contains(t, joined, "\nXDG_CONFIG_HOME=/isolated/.config\n")
	require.Contains(t, joined, "\nAGUARA_NO_UPDATE_CHECK=1\n")
	require.NotContains(t, joined, "/leaky-home")
	require.NotContains(t, joined, "/leaky-config")
	require.NotContains(t, joined, "AGUARA_INSECURE_INTEL=1")
}
