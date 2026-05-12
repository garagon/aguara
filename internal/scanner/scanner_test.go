package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
	"github.com/stretchr/testify/require"
)

// mockAnalyzer is a simple analyzer for testing the scanner orchestrator.
type mockAnalyzer struct {
	name     string
	findings []types.Finding
}

func (m *mockAnalyzer) Name() string { return m.name }

func (m *mockAnalyzer) Analyze(_ context.Context, target *scanner.Target) ([]types.Finding, error) {
	var result []types.Finding
	for _, f := range m.findings {
		f.FilePath = target.RelPath
		result = append(result, f)
	}
	return result, nil
}

func TestScannerOrchestrator(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.md"), []byte("content"), 0644))

	s := scanner.New(2)
	s.RegisterAnalyzer(&mockAnalyzer{
		name: "test",
		findings: []types.Finding{
			{RuleID: "R1", Severity: types.SeverityHigh, Line: 1},
		},
	})

	result, err := s.Scan(context.Background(), dir)
	require.NoError(t, err)
	require.Equal(t, 1, result.FilesScanned)
	require.Len(t, result.Findings, 1)
	require.Equal(t, "R1", result.Findings[0].RuleID)
}

func TestScannerDisabledRules(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.md"), []byte("content"), 0644))

	s := scanner.New(1)
	s.SetDisabledRules([]string{"GHA_PWN_REQUEST_001", "  TOXIC_001  ", "", "MISSING_ID"})
	s.RegisterAnalyzer(&mockAnalyzer{
		name: "test",
		findings: []types.Finding{
			// Suppressed: analyzer-emitted ID, exactly disabled
			{RuleID: "GHA_PWN_REQUEST_001", Severity: types.SeverityHigh, Line: 1},
			// Suppressed: whitespace around ID in disable list is trimmed
			{RuleID: "TOXIC_001", Severity: types.SeverityCritical, Line: 2},
			// Kept: not in the disable list
			{RuleID: "GHA_CHECKOUT_001", Severity: types.SeverityHigh, Line: 3},
		},
	})

	result, err := s.Scan(context.Background(), dir)
	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	require.Equal(t, "GHA_CHECKOUT_001", result.Findings[0].RuleID)
}

func TestScannerDisabledRulesEmpty(t *testing.T) {
	// Empty input must not stick a non-nil map on the scanner: passing an
	// empty list is the documented "disable nothing" path used when the
	// user has neither --disable-rule nor disable_rules: in .aguara.yml.
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.md"), []byte("content"), 0644))

	s := scanner.New(1)
	s.SetDisabledRules(nil)
	s.SetDisabledRules([]string{"   ", ""}) // whitespace-only list also no-ops
	s.RegisterAnalyzer(&mockAnalyzer{
		name: "test",
		findings: []types.Finding{
			{RuleID: "GHA_PWN_REQUEST_001", Severity: types.SeverityHigh, Line: 1},
		},
	})

	result, err := s.Scan(context.Background(), dir)
	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
}

func TestScannerSeverityFilter(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.md"), []byte("content"), 0644))

	s := scanner.New(1)
	s.SetMinSeverity(types.SeverityHigh)
	s.RegisterAnalyzer(&mockAnalyzer{
		name: "test",
		findings: []types.Finding{
			{RuleID: "R1", Severity: types.SeverityLow, Line: 1},
			{RuleID: "R2", Severity: types.SeverityHigh, Line: 2},
		},
	})

	result, err := s.Scan(context.Background(), dir)
	require.NoError(t, err)
	require.Len(t, result.Findings, 1)
	require.Equal(t, "R2", result.Findings[0].RuleID)
}

func TestScannerDuration(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.md"), []byte("content"), 0644))

	s := scanner.New(1)
	s.RegisterAnalyzer(&mockAnalyzer{name: "test"})

	result, err := s.Scan(context.Background(), dir)
	require.NoError(t, err)
	require.Greater(t, result.Duration, time.Duration(0))
}

func TestScannerCorrelationBonus(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.md"), []byte("line1\nline2\nline3\nline4\nline5"), 0644))

	s := scanner.New(1)
	s.RegisterAnalyzer(&mockAnalyzer{
		name: "corr",
		findings: []types.Finding{
			{RuleID: "A1", Severity: types.SeverityHigh, Line: 1, Category: "prompt-injection"},
			{RuleID: "A2", Severity: types.SeverityHigh, Line: 3, Category: "prompt-injection"},
		},
	})

	result, err := s.Scan(context.Background(), dir)
	require.NoError(t, err)
	require.Len(t, result.Findings, 2)
	// Both findings are within 5 lines, so they get correlation bonus
	for _, f := range result.Findings {
		require.Greater(t, f.Score, float64(0), "finding %s should have correlation bonus", f.RuleID)
	}
}

func TestScannerInlineIgnore(t *testing.T) {
	dir := t.TempDir()
	// Line 1: ignore directive for R1
	// Line 2: content where R1 finding is on line 2
	// Line 3: content where R2 finding is on line 3 (not ignored)
	content := "# aguara-ignore-next-line R1\nmatched by R1\nmatched by R2\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.md"), []byte(content), 0644))

	s := scanner.New(1)
	s.RegisterAnalyzer(&mockAnalyzer{
		name: "test",
		findings: []types.Finding{
			{RuleID: "R1", Severity: types.SeverityHigh, Line: 2},
			{RuleID: "R2", Severity: types.SeverityHigh, Line: 3},
		},
	})

	result, err := s.Scan(context.Background(), dir)
	require.NoError(t, err)
	require.Len(t, result.Findings, 1, "R1 on line 2 should be suppressed by ignore-next-line on line 1")
	require.Equal(t, "R2", result.Findings[0].RuleID)
}

func TestScannerInlineIgnoreAll(t *testing.T) {
	dir := t.TempDir()
	content := "# aguara-ignore\nmatched by R1 and R2\nmatched by R3\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.md"), []byte(content), 0644))

	s := scanner.New(1)
	s.RegisterAnalyzer(&mockAnalyzer{
		name: "test",
		findings: []types.Finding{
			{RuleID: "R1", Severity: types.SeverityHigh, Line: 1},
			{RuleID: "R2", Severity: types.SeverityMedium, Line: 1},
			{RuleID: "R3", Severity: types.SeverityHigh, Line: 3},
		},
	})

	result, err := s.Scan(context.Background(), dir)
	require.NoError(t, err)
	require.Len(t, result.Findings, 1, "R1 and R2 on line 1 should be suppressed by aguara-ignore on same line")
	require.Equal(t, "R3", result.Findings[0].RuleID)
}

func TestScannerContextCancellation(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.md"), []byte("content"), 0644))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	s := scanner.New(1)
	s.RegisterAnalyzer(&mockAnalyzer{name: "test"})

	_, err := s.Scan(ctx, dir)
	require.Error(t, err)
}
