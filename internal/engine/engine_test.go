package engine_test

import (
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

func TestDefaultAnalyzersRegisteredOnce(t *testing.T) {
	seen := make(map[string]bool)
	for _, a := range engine.DefaultAnalyzers() {
		require.Falsef(t, seen[a.Name()], "analyzer %s registered twice", a.Name())
		seen[a.Name()] = true
	}
}
