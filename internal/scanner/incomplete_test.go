package scanner_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
	"github.com/stretchr/testify/require"
)

type failingAnalyzer struct{ withFinding bool }

func (a failingAnalyzer) Name() string { return "test-failure" }
func (a failingAnalyzer) Analyze(context.Context, *scanner.Target) ([]types.Finding, error) {
	var findings []types.Finding
	if a.withFinding {
		findings = []types.Finding{{RuleID: "TEST_PARTIAL", Severity: types.SeverityHigh, MatchedText: "synthetic-secret"}}
	}
	return findings, errors.New("parser failed near synthetic-secret")
}

type completionProbe struct{ finalized, saved bool }

func (p *completionProbe) Accumulate(string, string) {}
func (p *completionProbe) Finalize() []types.Finding { p.finalized = true; return nil }
func (p *completionProbe) Save() error               { p.saved = true; return nil }

func TestIncompleteScanRejectsLoadFailure(t *testing.T) {
	for _, kind := range []string{"missing", "directory", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			bad := &scanner.Target{Path: filepath.Join(dir, "missing.txt"), RelPath: "bad.txt"}
			if kind == "directory" {
				bad.Path = dir
			}
			if kind == "oversize" {
				require.NoError(t, os.WriteFile(bad.Path, []byte("xx"), 0o600))
				bad.MaxFileSize = 1
			}
			s := scanner.New(2)
			probe := &completionProbe{}
			s.SetCrossFileAccumulator(probe)
			s.SetStateStore(probe)
			r, err := s.ScanTargets(context.Background(), []*scanner.Target{{RelPath: "good.txt", Content: []byte("good")}, bad})
			require.Error(t, err)
			require.ErrorIs(t, err, scanner.ErrIncompleteScan)
			if kind == "missing" {
				require.ErrorIs(t, err, os.ErrNotExist)
			}
			require.Nil(t, r, "an incomplete scan returns no result value")
			partial := requireIncomplete(t, err)
			require.Equal(t, 1, partial.FilesScanned, "the readable target is still scanned")
			reason := map[string]string{"missing": types.FailureReasonIO, "directory": types.FailureReasonNotRegular, "oversize": types.FailureReasonTooLarge}[kind]
			require.Equal(t, []types.ScanFailure{{Path: "bad.txt", Stage: types.FailureStageRead, Reason: reason}}, partial.Errors)
			require.True(t, probe.finalized, "cross-file correlation runs on the files that were read")
			require.False(t, probe.saved, "state is not persisted from an incomplete scan")
		})
	}
}

// requireIncomplete returns the partial result carried by an
// incomplete-scan error and checks its invariants.
func requireIncomplete(t *testing.T, err error) *scanner.ScanResult {
	t.Helper()
	var incomplete *scanner.IncompleteError
	require.ErrorAs(t, err, &incomplete)
	require.NotNil(t, incomplete.Result)
	require.True(t, incomplete.Result.Incomplete)
	require.NotEmpty(t, incomplete.Result.Errors)
	require.Equal(t, incomplete.Result.Errors, incomplete.Failures)
	require.GreaterOrEqual(t, incomplete.Result.FailedOperations, len(incomplete.Result.Errors))
	require.NotEqual(t, types.VerdictClean, incomplete.Result.Verdict, "an incomplete result is never clean")
	require.NotNil(t, incomplete.Result.Findings)
	return incomplete.Result
}

func TestIncompleteScanRejectsAnalyzerFailure(t *testing.T) {
	for _, withFinding := range []bool{false, true} {
		s := scanner.New(1)
		s.RegisterAnalyzer(failingAnalyzer{withFinding: withFinding})
		probe := &completionProbe{}
		s.SetCrossFileAccumulator(probe)
		s.SetStateStore(probe)
		r, err := s.ScanTargets(context.Background(), []*scanner.Target{{RelPath: "input.txt", Content: []byte("good")}})
		require.Error(t, err)
		require.ErrorIs(t, err, scanner.ErrIncompleteScan)
		require.Nil(t, r)
		require.NotContains(t, err.Error(), "synthetic-secret")
		partial := requireIncomplete(t, err)
		require.Equal(t, []types.ScanFailure{{Path: "input.txt", Stage: types.FailureStageAnalyze, Analyzer: "test-failure", Reason: types.FailureReasonError}}, partial.Errors)
		if withFinding {
			// A finding the analyzer reported before failing is kept, and
			// the verdict follows it.
			require.Len(t, partial.Findings, 1)
			require.Equal(t, "TEST_PARTIAL", partial.Findings[0].RuleID)
			require.Equal(t, types.VerdictBlock, partial.Verdict)
		} else {
			require.Empty(t, partial.Findings)
			require.Equal(t, types.VerdictFlag, partial.Verdict)
		}
		require.True(t, probe.finalized)
		require.False(t, probe.saved)
	}
}

// One analyzer failing on one file fails that file for that analyzer
// only: the other analyzers' findings on it and every other file's
// findings are kept, and repeated scans return the same partial result.
func TestIncompleteScanKeepsOtherAnalyzersAndFiles(t *testing.T) {
	var first *scanner.ScanResult
	for range 5 {
		s := scanner.New(3)
		s.RegisterAnalyzer(selectiveFailure{fail: "bad.md"})
		s.RegisterAnalyzer(markerAnalyzer{})
		_, err := s.ScanTargets(context.Background(), []*scanner.Target{
			{RelPath: "bad.md", Content: []byte("marker")},
			{RelPath: "good.md", Content: []byte("marker")},
			{RelPath: "plain.md", Content: []byte("nothing")},
		})
		partial := requireIncomplete(t, err)
		require.Equal(t, 3, partial.FilesScanned)
		require.Equal(t, []types.ScanFailure{{Path: "bad.md", Stage: types.FailureStageAnalyze, Analyzer: "selective", Reason: types.FailureReasonBudget}}, partial.Errors)
		var files []string
		for _, f := range partial.Findings {
			files = append(files, f.FilePath)
		}
		require.Equal(t, []string{"bad.md", "good.md"}, files)
		if first == nil {
			first = partial
			continue
		}
		require.Equal(t, first.Findings, partial.Findings)
		require.Equal(t, first.Errors, partial.Errors)
	}
}

type selectiveFailure struct{ fail string }

func (a selectiveFailure) Name() string { return "selective" }
func (a selectiveFailure) Analyze(_ context.Context, target *scanner.Target) ([]types.Finding, error) {
	if target.RelPath == a.fail {
		return nil, fmt.Errorf("input over budget: %w", types.ErrAnalysisBudget)
	}
	return nil, nil
}

type markerAnalyzer struct{}

func (markerAnalyzer) Name() string { return "marker" }
func (markerAnalyzer) Analyze(_ context.Context, target *scanner.Target) ([]types.Finding, error) {
	if !strings.Contains(target.StringContent(), "marker") {
		return nil, nil
	}
	return []types.Finding{{RuleID: "TEST_MARKER", Severity: types.SeverityCritical, FilePath: target.RelPath, Line: 1, Analyzer: "marker"}}, nil
}

// A canceled scan returns promptly with the partial result and an error
// matching both ErrIncompleteScan and the context's error.
func TestIncompleteScanCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s := scanner.New(1)
	s.RegisterAnalyzer(cancelingAnalyzer{cancel: cancel})
	_, err := s.ScanTargets(ctx, []*scanner.Target{
		{RelPath: "a.md", Content: []byte("x")},
		{RelPath: "b.md", Content: []byte("x")},
		{RelPath: "c.md", Content: []byte("x")},
	})
	require.ErrorIs(t, err, scanner.ErrIncompleteScan)
	require.ErrorIs(t, err, context.Canceled)
	require.Contains(t, err.Error(), "(canceled)", "the message says why")
	partial := requireIncomplete(t, err)
	require.Equal(t, 3, partial.FailedOperations, "every target not evaluated is accounted for")
	for _, f := range partial.Errors {
		require.Equal(t, types.FailureReasonCanceled, f.Reason)
	}
}

type cancelingAnalyzer struct{ cancel context.CancelFunc }

func (cancelingAnalyzer) Name() string { return "canceling" }
func (a cancelingAnalyzer) Analyze(ctx context.Context, _ *scanner.Target) ([]types.Finding, error) {
	a.cancel()
	return nil, ctx.Err()
}

// The bounded list keeps discovery failures (a path that could not be
// listed hides everything under it) ahead of read and analyzer failures,
// whatever their paths.
func TestIncompleteResultListsDiscoveryFailuresFirst(t *testing.T) {
	dir := t.TempDir()
	var paths []string
	for i := range types.MaxReportedFailures + 50 {
		name := fmt.Sprintf("f%03d.md", i)
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("xx"), 0o600))
		paths = append(paths, name)
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "zz.md"), []byte("x"), 0o600))
	// Inspecting a path below a regular file fails (not a directory).
	paths = append(paths, filepath.Join("zz.md", "inner.md"))
	s := scanner.New(4)
	s.SetMaxFileSize(1)
	_, err := s.ScanPaths(context.Background(), dir, paths)
	partial := requireIncomplete(t, err)
	require.Equal(t, types.MaxReportedFailures+51, partial.FailedOperations)
	require.Len(t, partial.Errors, types.MaxReportedFailures)
	require.Equal(t, types.ScanFailure{Path: filepath.Join("zz.md", "inner.md"), Stage: types.FailureStageDiscover, Reason: types.FailureReasonIO}, partial.Errors[0])
	require.Equal(t, "f000.md", partial.Errors[1].Path)
}

func TestIncompleteResultIsBoundedAndSorted(t *testing.T) {
	var targets []*scanner.Target
	for i := range types.MaxReportedFailures + 50 {
		targets = append(targets, &scanner.Target{Path: filepath.Join(t.TempDir(), "missing"), RelPath: fmt.Sprintf("f%03d.md", i)})
	}
	_, err := scanner.New(4).ScanTargets(context.Background(), targets)
	partial := requireIncomplete(t, err)
	require.Equal(t, types.MaxReportedFailures+50, partial.FailedOperations)
	require.Len(t, partial.Errors, types.MaxReportedFailures)
	require.Equal(t, "f000.md", partial.Errors[0].Path)
	require.Contains(t, err.Error(), "150 failed operation(s)")
}

func TestIncompleteScanDiagnosticIsBoundedAndStable(t *testing.T) {
	s := scanner.New(2)
	s.RegisterAnalyzer(failingAnalyzer{})
	for range 5 {
		r, err := s.ScanTargets(context.Background(), []*scanner.Target{
			{RelPath: "z.txt", Content: []byte("safe")},
			{RelPath: "a\n" + strings.Repeat("x", 500), Content: []byte("safe")},
		})
		require.Nil(t, r)
		require.ErrorIs(t, err, scanner.ErrIncompleteScan)
		require.Contains(t, err.Error(), `a\n`)
		require.NotContains(t, err.Error(), "\n")
		require.Contains(t, err.Error(), "2 failed operation(s)")
		require.Less(t, len(err.Error()), 300)
	}
}

func TestIncompleteScanDoesNotPersistAcrossCalls(t *testing.T) {
	s := scanner.New(1)
	_, err := s.ScanTargets(context.Background(), []*scanner.Target{{Path: filepath.Join(t.TempDir(), "missing")}})
	require.ErrorIs(t, err, scanner.ErrIncompleteScan)
	r, err := s.ScanTargets(context.Background(), []*scanner.Target{{RelPath: "ok.txt", Content: []byte("safe")}})
	require.NoError(t, err)
	require.Empty(t, r.Findings)
	require.Equal(t, 1, r.FilesScanned)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err = s.ScanTargets(ctx, nil)
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, r)
}

func TestIncompleteDiscoveryPreservesExclusions(t *testing.T) {
	for _, name := range []string{"node_modules", ".git", ".aguara", "ignored"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			child := filepath.Join(dir, name)
			require.NoError(t, os.Mkdir(child, 0o700))
			require.NoError(t, os.Chmod(child, 0))
			t.Cleanup(func() { _ = os.Chmod(child, 0o700) })
			td := scanner.TargetDiscovery{IgnorePatterns: []string{"ignored/**"}}
			targets, err := td.Discover(dir)
			require.NoError(t, err)
			require.Empty(t, targets)
		})
	}
}

func TestIncompleteDiscoveryDoesNotTreatDirectoryNamesAsFileExclusions(t *testing.T) {
	for _, name := range []string{"hidden", "images.png"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			child := filepath.Join(dir, name)
			require.NoError(t, os.Mkdir(child, 0o700))
			require.NoError(t, os.WriteFile(filepath.Join(child, "payload.md"), []byte("payload"), 0o600))
			td := scanner.TargetDiscovery{IgnorePatterns: []string{name}}
			targets, err := td.Discover(dir)
			require.NoError(t, err)
			require.Len(t, targets, 1, "a basename exclusion does not exclude directory descendants")
			require.NoError(t, os.Chmod(child, 0))
			t.Cleanup(func() { _ = os.Chmod(child, 0o700) })
			if _, err := os.ReadDir(child); err == nil {
				t.Skip("permissions not enforced")
			}
			td = scanner.TargetDiscovery{IgnorePatterns: []string{name}}
			targets, err = td.Discover(dir)
			require.NoError(t, err, "only a root failure stops discovery")
			require.Empty(t, targets)
			require.Len(t, td.Failures, 1, "the unreadable directory is reported, not dropped")
			require.ErrorIs(t, td.Failures[0], scanner.ErrIncompleteScan)
		})
	}
}

func TestIncompleteDiscoveryRejectsErrors(t *testing.T) {
	t.Run("missing root", func(t *testing.T) {
		td := scanner.TargetDiscovery{IgnoreProjectFile: true, IgnorePatterns: []string{"*"}}
		_, err := td.Discover(filepath.Join(t.TempDir(), "missing"))
		require.Error(t, err)
	})
	t.Run("ignore read failure", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.Mkdir(filepath.Join(dir, ".aguaraignore"), 0o700))
		td := scanner.TargetDiscovery{}
		_, err := td.Discover(dir)
		require.Error(t, err)
	})
	t.Run("unreadable subtree", func(t *testing.T) {
		dir := t.TempDir()
		child := filepath.Join(dir, "hidden")
		require.NoError(t, os.Mkdir(child, 0o700))
		require.NoError(t, os.Chmod(child, 0))
		t.Cleanup(func() { _ = os.Chmod(child, 0o700) })
		if _, err := os.ReadDir(child); err == nil {
			t.Skip("permissions not enforced")
		}
		require.NoError(t, os.WriteFile(filepath.Join(dir, "ok.md"), []byte("ok"), 0o600))
		td := scanner.TargetDiscovery{IgnoreProjectFile: true}
		targets, err := td.Discover(dir)
		require.NoError(t, err)
		require.Len(t, targets, 1, "the rest of the tree is still discovered")
		require.Len(t, td.Failures, 1)
		// A scan of the tree is incomplete and keeps the readable file.
		_, err = scanner.New(1).Scan(context.Background(), dir)
		require.Equal(t, 1, requireIncomplete(t, err).FilesScanned)
	})
}

func TestScanExplicitDirectorySymlink(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ok.txt"), []byte("good"), 0o600))
	link := filepath.Join(t.TempDir(), "linked-root")
	if err := os.Symlink(dir, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	s := scanner.New(1)
	r, err := s.Scan(context.Background(), link)
	require.NoError(t, err)
	require.Equal(t, 1, r.FilesScanned)
}
