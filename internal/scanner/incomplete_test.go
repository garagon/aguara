package scanner_test

import (
	"context"
	"errors"
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
			require.Nil(t, r)
			require.False(t, probe.finalized)
			require.False(t, probe.saved)
		})
	}
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
		require.False(t, probe.finalized)
		require.False(t, probe.saved)
	}
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
			targets, err = td.Discover(dir)
			require.ErrorIs(t, err, scanner.ErrIncompleteScan)
			require.Nil(t, targets)
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
		td := scanner.TargetDiscovery{IgnoreProjectFile: true}
		_, err := td.Discover(dir)
		require.Error(t, err)
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
