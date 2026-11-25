package scanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/garagon/aguara/internal/scanner"
	"github.com/garagon/aguara/internal/types"
	"github.com/stretchr/testify/require"
)

// The result names the target-owned policy that shaped it: the
// .aguaraignore that was read and the files whose inline directives
// removed findings. Callers use it to tell users the project's own
// files changed what was reported.
func TestScanRecordsAppliedTargetPolicy(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
	}
	write(".aguaraignore", "skipped.md\n")
	write("skipped.md", "anything\n")
	write("suppressed.md", "# aguara-ignore-next-line R1\nmatch\n")
	write("reported.md", "match\n")

	newScanner := func(policy bool) *scanner.Scanner {
		s := scanner.New(1)
		s.SetProjectPolicyEnabled(policy)
		s.RegisterAnalyzer(&mockAnalyzer{name: "test", findings: []types.Finding{{RuleID: "R1", Severity: types.SeverityHigh, Line: 2}}})
		return s
	}

	result, err := newScanner(true).Scan(context.Background(), dir)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(dir, ".aguaraignore"), result.TargetPolicy.IgnoreFile)
	require.Equal(t, []string{"suppressed.md"}, result.TargetPolicy.InlineSuppressed)

	result, err = newScanner(false).Scan(context.Background(), dir)
	require.NoError(t, err)
	require.Empty(t, result.TargetPolicy.IgnoreFile, "ignored policy is not reported as applied")
	require.Empty(t, result.TargetPolicy.InlineSuppressed)
	require.Len(t, result.Findings, 4, "every file is reported when target policy is ignored")
}

// An ignore source that excluded nothing did not change the result, and
// exclusions are attributed to the caller's patterns or the file's.
func TestScanAttributesExclusionsToTheirSource(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
	}
	write(".aguaraignore", "*.log\nnothing-matches.md\n")
	write("notes.md", "match\n")
	write("build.tmp", "match\n")

	s := scanner.New(1)
	s.SetProjectPolicyEnabled(true)
	s.SetIgnorePatterns([]string{"*.tmp"})
	result, err := s.Scan(context.Background(), dir)
	require.NoError(t, err)
	require.Empty(t, result.TargetPolicy.IgnoreFile, "the .aguaraignore matched no file")
	require.Equal(t, 1, result.TargetPolicy.IgnorePatternExclusions)

	write("debug.log", "match\n")
	result, err = s.Scan(context.Background(), dir)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(dir, ".aguaraignore"), result.TargetPolicy.IgnoreFile)
	require.Equal(t, 1, result.TargetPolicy.IgnorePatternExclusions)
}
