package types_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/types"
	"github.com/stretchr/testify/require"
)

// TestFindingFingerprintGolden pins the fingerprint algorithm. The expected
// value was produced by the v0.29.0-era baseline implementation for this
// finding; a change here would make every recorded baseline entry and every
// uploaded code-scanning alert look new.
func TestFindingFingerprintGolden(t *testing.T) {
	f := types.Finding{
		RuleID:      "PROMPT_INJECTION_001",
		Analyzer:    "pattern",
		FilePath:    "demo/SKILL.md",
		MatchedText: "Ignore all previous instructions",
	}
	require.Equal(t, "0e50d62d07f615a5b70a595aa5df3d0f70da134565c97a8f3f4a3718630cf517", types.FindingFingerprint(f))

	// Independent re-derivation of the documented algorithm.
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s", f.RuleID, f.Analyzer, f.FilePath, f.MatchedText)
	require.Equal(t, hex.EncodeToString(h.Sum(nil)), types.FindingFingerprint(f))

	// Path separators and whitespace are normalized.
	g := f
	g.FilePath = `demo\SKILL.md`
	g.MatchedText = "  Ignore   all previous\tinstructions "
	require.Equal(t, types.FindingFingerprint(f), types.FindingFingerprint(g))
}

func TestFingerprintableMirrorsRedaction(t *testing.T) {
	require.True(t, types.Fingerprintable(types.Finding{Category: "prompt-injection"}))
	require.False(t, types.Fingerprintable(types.Finding{Category: "credential-leak"}))
	require.False(t, types.Fingerprintable(types.Finding{Category: "exfiltration", Sensitive: true}))
}

func TestFindingMarshalJSONAddsLabelFingerprintAndRounds(t *testing.T) {
	f := types.Finding{
		RuleID:      "PROMPT_INJECTION_001",
		Severity:    types.SeverityHigh,
		Category:    "prompt-injection",
		Analyzer:    "pattern",
		FilePath:    "demo/SKILL.md",
		MatchedText: "Ignore all previous instructions",
		Confidence:  0.9900000000000001,
		Score:       16.500000000000004,
		AlsoMatched: []types.MergedFinding{{RuleID: "EXTDL_013", Severity: types.SeverityMedium, Category: "external-download"}},
	}
	out, err := json.Marshal(f)
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(out, &got))

	require.Equal(t, float64(3), got["severity"], "severity stays numeric")
	require.Equal(t, "HIGH", got["severity_label"])
	require.Equal(t, types.FindingFingerprint(f), got["fingerprint"])
	require.Equal(t, 0.99, got["confidence"])
	require.Equal(t, 16.5, got["score"])
	require.NotContains(t, string(out), "0000000")

	also := got["also_matched"].([]any)
	require.Len(t, also, 1)
	entry := also[0].(map[string]any)
	require.Equal(t, "EXTDL_013", entry["rule_id"])
	require.Equal(t, float64(2), entry["severity"])
	require.Equal(t, "MEDIUM", entry["severity_label"])
	require.Equal(t, "external-download", entry["category"])
	require.NotContains(t, entry, "matched_text")

	// The in-memory values are not rounded.
	require.Equal(t, 0.9900000000000001, f.Confidence)
}

func TestFindingMarshalJSONOmitsFingerprintForRedactedFindings(t *testing.T) {
	for _, f := range []types.Finding{
		{RuleID: "CRED_002", Category: "credential-leak", MatchedText: types.RedactedPlaceholder},
		{RuleID: "MCP_007", Category: "mcp-attack", Sensitive: true, MatchedText: types.RedactedPlaceholder},
	} {
		out, err := json.Marshal(f)
		require.NoError(t, err)
		require.NotContains(t, string(out), `"fingerprint"`)
		require.Contains(t, string(out), `"severity_label":"INFO"`)
	}
}

func TestScanResultMarshalJSONAddsVerdictLabelAndRoundsRisk(t *testing.T) {
	cases := map[types.Verdict]string{
		types.VerdictClean: "clean",
		types.VerdictFlag:  "flag",
		types.VerdictBlock: "block",
	}
	for verdict, label := range cases {
		out, err := json.Marshal(types.ScanResult{Verdict: verdict, RiskScore: 87.50000000000001})
		require.NoError(t, err)
		require.Contains(t, string(out), fmt.Sprintf(`"verdict":%d`, verdict))
		require.Contains(t, string(out), `"verdict_label":"`+label+`"`)
		require.Contains(t, string(out), `"risk_score":87.5`)
	}
}

func TestSuppressionSummaryJSONAndArithmetic(t *testing.T) {
	s := &types.SuppressionSummary{Deduplicated: 2, BelowMinSeverity: 1, ExcludedFiles: 4}
	s.Add(&types.SuppressionSummary{DisabledRules: 1, ToolExemptions: 1, InlineDirectives: 1})
	require.Equal(t, 6, s.Findings(), "excluded files are not findings")
	var nilSummary *types.SuppressionSummary
	require.Equal(t, 0, nilSummary.Findings())

	out, err := json.Marshal(types.ScanResult{Suppressed: s})
	require.NoError(t, err)
	for _, key := range []string{"deduplicated", "below_min_severity", "disabled_rules", "tool_exemptions", "inline_directives", "excluded_files"} {
		require.True(t, strings.Contains(string(out), `"`+key+`":`), "missing %s in %s", key, out)
	}
}
