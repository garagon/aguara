package scanner_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
	"github.com/stretchr/testify/require"
)

func scanVerdict(t *testing.T, profile types.ScanProfile, enforced []string, findings []types.Finding) types.Verdict {
	t.Helper()
	s := scanner.New(1)
	s.SetScanProfile(profile)
	s.SetProfileEnforcedRules(enforced)
	s.SetDeduplicateMode(types.DeduplicateSameRuleOnly)
	s.RegisterAnalyzer(&mockAnalyzer{name: "mock", findings: findings})
	result, err := s.ScanTargets(context.Background(), []*scanner.Target{{RelPath: "x.md", Content: []byte("x\n")}})
	require.NoError(t, err)
	return result.Verdict
}

// TestVerdictMatrixWithoutEnforcedRules pins the verdict for every profile
// and highest severity when the caller does not name enforced rules.
func TestVerdictMatrixWithoutEnforcedRules(t *testing.T) {
	const (
		clean = types.VerdictClean
		flag  = types.VerdictFlag
		block = types.VerdictBlock
	)
	severities := []types.Severity{types.SeverityInfo, types.SeverityLow, types.SeverityMedium, types.SeverityHigh, types.SeverityCritical}
	want := map[types.ScanProfile][]types.Verdict{
		types.ProfileStrict:       {flag, flag, flag, block, block},
		types.ProfileContentAware: {clean, clean, clean, flag, flag},
		types.ProfileMinimal:      {clean, clean, clean, flag, flag},
	}
	for profile, verdicts := range want {
		require.Equal(t, clean, scanVerdict(t, profile, nil, nil), "profile %d without findings", profile)
		for i, sev := range severities {
			findings := []types.Finding{
				{RuleID: "OTHER_RULE", Severity: types.SeverityInfo, Line: 1},
				{RuleID: "MAIN_RULE", Severity: sev, Line: 1},
			}
			require.Equal(t, verdicts[i], scanVerdict(t, profile, nil, findings),
				fmt.Sprintf("profile %d, highest severity %s", profile, sev))
		}
	}
}

// TestEnforcedRuleVerdictIsMonotonic: an enforced LOW rule blocked under
// content-aware but only flagged under strict, so the default profile was
// more lenient than a relaxed one. An enforced finding now blocks under
// every profile except minimal, which never blocks.
func TestEnforcedRuleVerdictIsMonotonic(t *testing.T) {
	enforced := []string{"enforced_rule"}
	for _, sev := range []types.Severity{types.SeverityInfo, types.SeverityLow, types.SeverityMedium, types.SeverityCritical} {
		findings := []types.Finding{{RuleID: "ENFORCED_RULE", Severity: sev, Line: 1}}
		require.Equal(t, types.VerdictBlock, scanVerdict(t, types.ProfileStrict, enforced, findings), "strict, enforced %s", sev)
		require.Equal(t, types.VerdictBlock, scanVerdict(t, types.ProfileContentAware, enforced, findings), "content-aware, enforced %s", sev)
		require.Equal(t, types.VerdictFlag, scanVerdict(t, types.ProfileMinimal, enforced, findings), "minimal, enforced %s", sev)
		require.Equal(t, types.VerdictBlock, scanVerdict(t, types.ScanProfile(99), enforced, findings), "unknown profile, enforced %s", sev)
	}

	// Without an enforced finding the enforced list changes nothing.
	other := []types.Finding{{RuleID: "OTHER_RULE", Severity: types.SeverityLow, Line: 1}}
	require.Equal(t, types.VerdictFlag, scanVerdict(t, types.ProfileStrict, enforced, other))
	require.Equal(t, types.VerdictClean, scanVerdict(t, types.ProfileContentAware, enforced, other))
	require.Equal(t, types.VerdictClean, scanVerdict(t, types.ProfileMinimal, enforced, other))
	require.Equal(t, types.VerdictClean, scanVerdict(t, types.ProfileStrict, enforced, nil))
}
