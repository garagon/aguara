package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
	"github.com/stretchr/testify/require"
)

// observingAccumulator records the findings the scanner hands to a
// CrossFileFindingObserver and emits one cross-file finding of its own.
type observingAccumulator struct {
	mu       sync.Mutex
	observed map[string][]string
	content  map[string]bool
}

func newObservingAccumulator() *observingAccumulator {
	return &observingAccumulator{observed: map[string][]string{}, content: map[string]bool{}}
}

func (o *observingAccumulator) Accumulate(relPath, _ string) {
	o.mu.Lock()
	o.content[relPath] = true
	o.mu.Unlock()
}

func (o *observingAccumulator) ObserveFindings(relPath string, findings []types.Finding) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, f := range findings {
		o.observed[relPath] = append(o.observed[relPath], f.RuleID)
	}
	sort.Strings(o.observed[relPath])
}

func (o *observingAccumulator) Finalize() []types.Finding {
	return []types.Finding{{RuleID: "CROSS_001", Severity: types.SeverityHigh, FilePath: "a.sh", Line: 1}}
}

// plainAccumulator implements only the original interface.
type plainAccumulator struct{ finalized bool }

func (p *plainAccumulator) Accumulate(string, string) {}
func (p *plainAccumulator) Finalize() []types.Finding {
	p.finalized = true
	return nil
}

func TestCrossFileObserverReceivesPerFileFindings(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.sh"), []byte("echo a\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.md"), []byte("aguara-ignore RULE_IGNORED\n"), 0o644))

	s := scanner.New(2)
	s.RegisterAnalyzer(&mockAnalyzer{name: "first", findings: []types.Finding{
		{RuleID: "RULE_KEPT", Severity: types.SeverityHigh, Line: 1},
		{RuleID: "RULE_DISABLED", Severity: types.SeverityCritical, Line: 1},
	}})
	s.RegisterAnalyzer(&mockAnalyzer{name: "second", findings: []types.Finding{
		{RuleID: "RULE_IGNORED", Severity: types.SeverityHigh, Line: 1},
	}})
	s.SetDisabledRules([]string{"RULE_DISABLED"})
	acc := newObservingAccumulator()
	s.SetCrossFileAccumulator(acc)

	result, err := s.Scan(context.Background(), dir)
	require.NoError(t, err)

	// Both analyzers' findings arrive together, after disabled rules and
	// inline suppressions are applied. The accumulator's own Finalize
	// output is reported but never observed.
	require.Equal(t, map[string][]string{
		"a.sh": {"RULE_IGNORED", "RULE_KEPT"},
		"b.md": {"RULE_KEPT"},
	}, acc.observed)
	var cross int
	for _, f := range result.Findings {
		if f.RuleID == "CROSS_001" {
			cross++
		}
	}
	require.Equal(t, 1, cross)
}

func TestCrossFileObserverNotRequired(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.sh"), []byte("echo a\n"), 0o644))

	s := scanner.New(1)
	s.RegisterAnalyzer(&mockAnalyzer{name: "first", findings: []types.Finding{
		{RuleID: "RULE_KEPT", Severity: types.SeverityHigh, Line: 1},
	}})
	acc := &plainAccumulator{}
	s.SetCrossFileAccumulator(acc)

	result, err := s.Scan(context.Background(), dir)
	require.NoError(t, err)
	require.True(t, acc.finalized)
	require.Len(t, result.Findings, 1)
}
