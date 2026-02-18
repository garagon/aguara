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
