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
	r, err := s.ScanChangedPaths(context.Background(), root, []string{"mod", "top.md"}, map[string]scanner.Submodule{"mod": {Recorded: "c1", Head: "c1"}})
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
	_, err := s.ScanChangedPaths(context.Background(), root, []string{"a.md", "empty", "absent", "deleted.md"}, map[string]scanner.Submodule{"empty": {Recorded: "c1"}, "absent": {Recorded: "c1"}})
	partial := requireIncomplete(t, err)
	require.Equal(t, 1, partial.FilesScanned)
	require.Equal(t, []types.ScanFailure{
		{Path: "absent", Stage: types.FailureStageDiscover, Reason: types.FailureReasonNotScanned},
		{Path: "empty", Stage: types.FailureStageDiscover, Reason: types.FailureReasonNotScanned},
	}, partial.Errors)
	require.Contains(t, err.Error(), "not checked out")
}

// A submodule checked out at another commit than the recorded one (or at
// an unknown one) is scanned as it is, and the scan is incomplete: the
// recorded commit was not read.
func TestScanPathsSubmoduleAtAnotherCommitIsIncomplete(t *testing.T) {
	for name, sm := range map[string]scanner.Submodule{
		"other commit":   {Recorded: "c1", Head: "c2"},
		"unknown commit": {Recorded: "c1"},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			require.NoError(t, os.Mkdir(filepath.Join(root, "mod"), 0o700))
			require.NoError(t, os.WriteFile(filepath.Join(root, "mod", "SKILL.md"), []byte("x"), 0o600))
			s := scanner.New(1)
			s.RegisterAnalyzer(pathAnalyzer{})
			_, err := s.ScanChangedPaths(context.Background(), root, []string{"mod"}, map[string]scanner.Submodule{"mod": sm})
			partial := requireIncomplete(t, err)
			require.Equal(t, 1, partial.FilesScanned, "the work tree is still scanned")
			require.Len(t, partial.Findings, 1)
			require.Equal(t, []types.ScanFailure{{Path: "mod", Stage: types.FailureStageDiscover, Reason: types.FailureReasonNotScanned}}, partial.Errors)
			require.Contains(t, err.Error(), "recorded commit not checked out")
		})
	}
}

// A submodule checked out at the recorded commit that holds no scannable
// files (only binary files here) was reported as not checked out. It is
// complete and adds no files; so is a listed directory that is not a
// submodule.
func TestScanPathsCheckedOutSubmoduleWithoutScannableFilesIsComplete(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"mod", "plain"} {
		require.NoError(t, os.Mkdir(filepath.Join(root, dir), 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(root, dir, "logo.png"), []byte("x"), 0o600))
	}
	require.NoError(t, os.WriteFile(filepath.Join(root, "a.md"), []byte("x"), 0o600))
	s := scanner.New(1)
	r, err := s.ScanChangedPaths(context.Background(), root, []string{"a.md", "mod", "plain"}, map[string]scanner.Submodule{"mod": {Recorded: "c1", Head: "c1"}})
	require.NoError(t, err)
	require.False(t, r.Incomplete)
	require.Equal(t, 1, r.FilesScanned)
	require.Empty(t, r.Errors)
}
