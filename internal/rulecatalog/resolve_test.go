package rulecatalog_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/garagon/aguara/internal/rulecatalog"
	"github.com/garagon/aguara/internal/rules"
	"github.com/garagon/aguara/internal/types"
	"github.com/stretchr/testify/require"
)

func TestResolveBuiltinConfigurationHasNoProblems(t *testing.T) {
	res, err := rulecatalog.Resolve(rulecatalog.Input{})
	require.NoError(t, err)
	require.Empty(t, res.Problems, "built-in rules must compile and have unique IDs")
	require.NotEmpty(t, res.Compiled)
}

// TestResolveRecordsProblemsAndSkipsInputs locks the contract callers rely
// on: problems with individual inputs are recorded, the offending input is
// skipped, and everything else still resolves.
func TestResolveRecordsProblemsAndSkipsInputs(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte(`id: GOOD_001
name: Good
severity: HIGH
category: custom
patterns:
  - type: contains
    value: good-marker
---
id: BAD_001
name: Bad
severity: HIGH
category: custom
patterns:
  - type: regex
    value: "(unclosed"
---
id: CRED_002
name: Collides
severity: LOW
category: custom
patterns:
  - type: contains
    value: collide-marker
`), 0o600))

	res, err := rulecatalog.Resolve(rulecatalog.Input{
		CustomRulesDirs: []string{dir},
		Disabled:        []rulecatalog.Ref{{ID: "nope_001", Source: "test"}, {ID: "good_001", Source: "test"}},
		Overrides: []rulecatalog.OverrideRef{
			{ID: "PROMPT_INJECTION_001", Source: "test", Override: rules.RuleOverride{Severity: "severe", Disabled: false}},
			{ID: "UNKNOWN_002", Source: "test", Override: rules.RuleOverride{Disabled: true}},
		},
	})
	require.NoError(t, err)

	kinds := map[types.ConfigProblemKind][]string{}
	for _, p := range res.Problems {
		kinds[p.Kind] = append(kinds[p.Kind], p.RuleID)
	}
	require.Equal(t, []string{"BAD_001"}, kinds[types.ConfigProblemInvalidRule])
	require.Equal(t, []string{"CRED_002"}, kinds[types.ConfigProblemDuplicateRuleID])
	require.Equal(t, []string{"UNKNOWN_002", "nope_001"}, kinds[types.ConfigProblemUnknownRuleID])
	require.Equal(t, []string{"PROMPT_INJECTION_001"}, kinds[types.ConfigProblemInvalidSeverity])

	require.Equal(t, []string{"GOOD_001"}, res.Disabled)
	require.Equal(t, "", res.Overrides["PROMPT_INJECTION_001"].Severity, "invalid severity is cleared")
	creds := 0
	for _, r := range res.Compiled {
		require.NotEqual(t, "BAD_001", r.ID)
		require.NotEqual(t, "GOOD_001", r.ID, "disabled rule must not be compiled in")
		if r.ID == "CRED_002" {
			creds++
			require.NotEqual(t, "Collides", r.Name, "the built-in rule wins")
		}
	}
	require.Equal(t, 1, creds)
}

func TestResolveUnreadableDirectoryIsAnError(t *testing.T) {
	_, err := rulecatalog.Resolve(rulecatalog.Input{CustomRulesDirs: []string{filepath.Join(t.TempDir(), "missing")}})
	require.Error(t, err)
}
