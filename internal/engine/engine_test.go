package engine_test

import (
	"slices"
	"testing"

	"github.com/garagon/aguara/internal/engine"
	"github.com/garagon/aguara/internal/rules"
	"github.com/garagon/aguara/internal/rules/builtin"
	"github.com/stretchr/testify/require"
)

// Catalog lookups key rules by ID, so a duplicate would silently replace
// another rule's name, severity and category in scan output and explain.
func TestRuleMetadataIDsAreUniqueAndAttributed(t *testing.T) {
	owner := make(map[string]string)
	for _, r := range engine.RuleMetadata() {
		require.NotEmpty(t, r.ID)
		require.NotEmptyf(t, r.Analyzer, "%s must name the analyzer that emits it", r.ID)
		if prev, ok := owner[r.ID]; ok {
			t.Errorf("rule %s is declared by both %s and %s", r.ID, prev, r.Analyzer)
		}
		owner[r.ID] = r.Analyzer
	}

	raw, err := rules.LoadFromFS(builtin.FS())
	require.NoError(t, err)
	for _, r := range raw {
		if analyzer, ok := owner[r.ID]; ok {
			t.Errorf("rule %s is both a YAML pattern rule and emitted by %s", r.ID, analyzer)
		}
	}
}

func TestDefaultAnalyzersOrder(t *testing.T) {
	var names []string
	for _, a := range engine.DefaultAnalyzers() {
		require.NotContainsf(t, names, a.Name(), "analyzer %s registered twice", a.Name())
		names = append(names, a.Name())
	}
	// ci-trust must run before toxicflow so its chain findings are
	// deduplicated and correlated alongside leaf signals.
	ci, toxic := slices.Index(names, "ci-trust"), slices.Index(names, "toxicflow")
	require.NotEqual(t, -1, ci, "ci-trust must be a default analyzer")
	require.NotEqual(t, -1, toxic, "toxicflow must be a default analyzer")
	require.Less(t, ci, toxic, "ci-trust must run before toxicflow: %v", names)
}
