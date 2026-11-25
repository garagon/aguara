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

// severityRecorder records the severity each observed finding carries.
type severityRecorder struct {
	mu   sync.Mutex
	seen map[string]types.Severity // "path RULE" -> severity
}

func (r *severityRecorder) Accumulate(string, string) {}
func (r *severityRecorder) Finalize() []types.Finding { return nil }
func (r *severityRecorder) ObserveFindings(relPath string, findings []types.Finding) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, f := range findings {
		r.seen[relPath+" "+f.RuleID] = f.Severity
	}
}

// Observers see the severity the report shows: overrides are applied before
// observation, a fenced finding in ordinary documentation is lowered once
// (not once for the observed copy and again for the report), and a fenced
// finding in SKILL.md keeps the override.
func TestCrossFileObserverSeesOverriddenSeverity(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.sh", "doc.md", "SKILL.md"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("x\n"), 0o644))
	}
	s := scanner.New(2)
	s.RegisterAnalyzer(&mockAnalyzer{name: "behavior", findings: []types.Finding{
		{RuleID: "RULE_DOWN", Severity: types.SeverityHigh, Line: 1},
		{RuleID: "RULE_UP", Severity: types.SeverityMedium, Line: 1},
		{RuleID: "RULE_FENCED", Severity: types.SeverityMedium, Line: 1, InCodeBlock: true},
		{RuleID: "RULE_PLAIN", Severity: types.SeverityMedium, Line: 1},
	}})
	s.SetSeverityOverrides(map[string]types.Severity{
		"rule_down":   types.SeverityLow,
		"RULE_UP":     types.SeverityCritical,
		"Rule_Fenced": types.SeverityHigh,
	})
	s.SetDeduplicateMode(types.DeduplicateSameRuleOnly)
	rec := &severityRecorder{seen: map[string]types.Severity{}}
	s.SetCrossFileAccumulator(rec)

	result, err := s.Scan(context.Background(), dir)
	require.NoError(t, err)

	want := map[string]types.Severity{}
	for _, f := range result.Findings {
		want[f.FilePath+" "+f.RuleID] = f.Severity
	}
	require.Equal(t, want, rec.seen, "observers see exactly the reported severities")
	require.Equal(t, types.SeverityLow, rec.seen["a.sh RULE_DOWN"])
	require.Equal(t, types.SeverityCritical, rec.seen["a.sh RULE_UP"])
	require.Equal(t, types.SeverityMedium, rec.seen["a.sh RULE_PLAIN"])
	require.Equal(t, types.SeverityMedium, rec.seen["doc.md RULE_FENCED"], "fenced documentation finding lowered once")
	require.Equal(t, types.SeverityHigh, rec.seen["SKILL.md RULE_FENCED"], "SKILL.md keeps the override")
}
