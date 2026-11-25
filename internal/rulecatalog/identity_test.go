package rulecatalog_test

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/garagon/aguara/internal/rulecatalog"
	"github.com/garagon/aguara/internal/rules"
	"github.com/stretchr/testify/require"
)

func resolve(t *testing.T, in rulecatalog.Input) *rulecatalog.Resolution {
	t.Helper()
	res, err := rulecatalog.Resolve(in)
	require.NoError(t, err)
	require.Empty(t, res.Problems)
	return res
}

func TestIdentityCountsAndStableDigest(t *testing.T) {
	a := resolve(t, rulecatalog.Input{}).Identity()
	b := resolve(t, rulecatalog.Input{}).Identity()
	require.Equal(t, a, b, "the digest is deterministic")
	require.Regexp(t, `^sha256:[0-9a-f]{64}$`, a.Digest)
	require.Equal(t, a.Detections, a.PatternRules+a.AnalyzerRules)
	require.Positive(t, a.PatternRules)
	require.Positive(t, a.AnalyzerRules)
	require.Len(t, resolve(t, rulecatalog.Input{}).Catalog(""), a.Detections)
}

func TestIdentityDigestTracksRuleSetChanges(t *testing.T) {
	base := resolve(t, rulecatalog.Input{}).Identity()

	disabled := resolve(t, rulecatalog.Input{Disabled: []rulecatalog.Ref{{ID: "CRED_002", Source: "test"}}}).Identity()
	require.NotEqual(t, base.Digest, disabled.Digest)
	require.Equal(t, base.Detections-1, disabled.Detections)

	analyzerOff := resolve(t, rulecatalog.Input{Disabled: []rulecatalog.Ref{{ID: "JS_OBF_001", Source: "test"}}}).Identity()
	require.NotEqual(t, base.Digest, analyzerOff.Digest)
	require.Equal(t, base.AnalyzerRules-1, analyzerOff.AnalyzerRules)

	rerated := resolve(t, rulecatalog.Input{Overrides: []rulecatalog.OverrideRef{{
		ID: "PROMPT_INJECTION_001", Source: "test", Override: rules.RuleOverride{Severity: "LOW"},
	}}}).Identity()
	require.NotEqual(t, base.Digest, rerated.Digest)
	require.Equal(t, base.Detections, rerated.Detections)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "r.yaml"), []byte(`id: TEAM_001
name: Team rule
severity: HIGH
category: custom
patterns:
  - type: contains
    value: internal-only
`), 0o600))
	custom := resolve(t, rulecatalog.Input{CustomRulesDirs: []string{dir}}).Identity()
	require.NotEqual(t, base.Digest, custom.Digest)
	require.Equal(t, base.PatternRules+1, custom.PatternRules)
}

func TestCatalogCWEIdentifiersAreWellFormed(t *testing.T) {
	re := regexp.MustCompile(`^CWE-[1-9][0-9]*$`)
	mapped := map[string][]string{}
	for _, r := range resolve(t, rulecatalog.Input{}).Catalog("") {
		for _, id := range r.CWE {
			require.Regexp(t, re, id, r.ID)
		}
		if len(r.CWE) > 0 {
			mapped[r.ID] = r.CWE
		}
	}
	// The first set of mappings, pattern and analyzer rules alike.
	require.Equal(t, []string{"CWE-798"}, mapped["CRED_002"])
	require.Equal(t, []string{"CWE-494"}, mapped["EXTDL_013"])
	require.Equal(t, []string{"CWE-494"}, mapped["AGENTCFG_HOOK_FETCH_EXEC_001"])
	require.Equal(t, []string{"CWE-732"}, mapped["PY_WORLD_WRITABLE_001"])
	require.NotContains(t, mapped, "PROMPT_INJECTION_001", "ambiguous mappings stay unmapped")
}
