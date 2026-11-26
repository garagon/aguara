package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
)

type pathAnalyzer struct{}

func (pathAnalyzer) Name() string { return "paths" }
func (pathAnalyzer) Analyze(_ context.Context, target *scanner.Target) ([]types.Finding, error) {
	return []types.Finding{{RuleID: "TEST_PATH", Severity: types.SeverityHigh, FilePath: target.RelPath, Line: 1, Analyzer: "paths"}}, nil
}

// A changed path that is a directory (git lists a changed submodule by its
// path) is walked, and its files are reported under that path.
func TestScanPathsWalksChangedDirectory(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "mod", "docs"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(root, "mod", "SKILL.md"), []byte("x"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "mod", "docs", "a.md"), []byte("x"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "top.md"), []byte("x"), 0o600))
	s := scanner.New(2)
	s.RegisterAnalyzer(pathAnalyzer{})
	r, err := s.ScanPaths(context.Background(), root, []string{"mod", "top.md"}, map[string]bool{"mod": true})
	require.NoError(t, err)
	require.Equal(t, 3, r.FilesScanned)
	var files []string
	for _, f := range r.Findings {
		files = append(files, f.FilePath)
	}
	require.ElementsMatch(t, []string{filepath.Join("mod", "SKILL.md"), filepath.Join("mod", "docs", "a.md"), "top.md"}, files)
	require.Empty(t, r.Skipped)
}

// A submodule that is not checked out (an empty or absent directory) was
// not scanned, so the scan is incomplete rather than clean. A deleted file
// is still just left out.
func TestScanPathsNotCheckedOutSubmoduleIsIncomplete(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, "empty"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(root, "a.md"), []byte("x"), 0o600))
	s := scanner.New(1)
	s.RegisterAnalyzer(pathAnalyzer{})
	_, err := s.ScanPaths(context.Background(), root, []string{"a.md", "empty", "absent", "deleted.md"}, map[string]bool{"empty": true, "absent": true})
	partial := requireIncomplete(t, err)
	require.Equal(t, 1, partial.FilesScanned)
	require.Equal(t, []types.ScanFailure{
		{Path: "absent", Stage: types.FailureStageDiscover, Reason: types.FailureReasonNotScanned},
		{Path: "empty", Stage: types.FailureStageDiscover, Reason: types.FailureReasonNotScanned},
	}, partial.Errors)
	require.Contains(t, err.Error(), "not checked out")
}
